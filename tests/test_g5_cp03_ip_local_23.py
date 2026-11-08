"""CP03-23 source-first two-command local ip -j source originals and adverse tests.

All receipts are synthetic and sealed locally; tests never call ip or netlink.
Source contract authority: G4-07 SRC-23 fixed D1 plans + engine subcall mapping.
"""
import hashlib, json, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import command_plan
from lbt_g5.normalization import normalize_sealed_source, parser_available, SourceParseError
from lbt_g5.safety import initial_source_policies

RUN="run-2026305120000"
ADDR=(b'[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],'
      b'"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]}]\n')
ROUTE=(b'[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp",'
       b'"metric":100},{"dst":"198.51.100.0/24","dev":"eth0","scope":"link"}]\n')
COMMANDS=("ip -j addr show","ip -j route show")
POL={x.source_id:x for x in initial_source_policies()}["SRC-23"]

class IpLocalOracle(unittest.TestCase):
    def direct(self,kind,raw):
        return normalize_sealed_source("SRC-23",raw,source_stream="stdout",
                                       source_command=COMMANDS[0 if kind=="addr" else 1])

    def make(self, *, variants=None, items=None, omit=None, tamper=None):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        folder=Path(td.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        records=[]
        artifacts=[]
        variants=variants or {}
        items=items or {
          "01":(("call0001-stdout",ADDR),),
          "02":(("call0002-stdout",ROUTE),)
        }
        for attempt,ls in items.items():
            if attempt==omit:continue
            sealed=[]
            for name,raw in ls:
                receipt=writer.seal_chunks(POL,attempt,name,(raw,)).receipt
                self.assertIsNotNone(receipt)
                sealed.append(receipt)
                artifacts.append(receipt)
            v=variants.get(attempt,{})
            attrs=dict(invocation=COMMANDS[int(attempt)-1] if attempt in ("01","02") else COMMANDS[0],
                       evidence=tuple(sealed),bytes_count=sum(x.byte_count for x in sealed),
                       exit_code=0,source_paths=(),target=None)
            attrs.update(v.get("attrs",{}))
            record=build_attempt(RUN,"SRC-23",attempt,"ALLOW",
                                 v.get("outcome","CAPTURED"),v.get("reason","BYTES_PRESERVED"),
                                 **attrs)
            path=commit_attempt(str(folder),record)
            records.append(SimpleNamespace(receipt_private_path=path,
                         outcome=SimpleNamespace(artifacts=tuple(sealed))))
        if tamper is not None:
            (folder/artifacts[tamper].private_relative_path).write_bytes(b"tampered\n")
        run=EngineRun(RUN,(CollectorRun("COL-NET",tuple(records)),))
        return folder,run,artifacts

    def test_authority_two_fixed_commands_and_parser_registration(self):
        self.assertEqual((POL.authorization_class,POL.operation_id,POL.max_entries,POL.max_seconds),
                         ("D1","IP_LOCAL",2,10))
        self.assertEqual(command_plan("SRC-23",0).argv,("ip","-j","addr","show"))
        self.assertEqual(command_plan("SRC-23",1).argv,("ip","-j","route","show"))
        self.assertTrue(parser_available("SRC-23"))

    def test_exact_addr_interface_fields_and_nested_json(self):
        r=self.direct("addr",ADDR)
        self.assertEqual(r.parser_id,"linux-iproute2-json-local-v1")
        d=r.values[0]
        self.assertEqual((d.datum_path,d.value_type),
                         ("network.ip.local_addresses.reported","ARRAY"))
        self.assertEqual(d.normalized_value[0]["ifindex"],1)
        self.assertEqual(d.normalized_value[0]["ifname"],"lo")
        self.assertEqual(d.normalized_value[0]["addr_info"][0]["local"],"127.0.0.1")

    def test_exact_route_attributes_and_no_reachability_claim(self):
        r=self.direct("route",ROUTE)
        d=r.values[0]
        self.assertEqual(d.datum_path,"network.ip.local_routes.reported")
        self.assertEqual(d.normalized_value[0]["dst"],"default")
        self.assertEqual(d.normalized_value[0]["gateway"],"192.0.2.1")
        self.assertEqual(d.normalized_value[0]["metric"],100)
        self.assertNotIn("reachable",str(d.normalized_value).lower())

    def test_empty_addr_and_route_array_is_observed_not_inferred(self):
        for kind in ("addr","route"):
            with self.subTest(kind=kind):
                self.assertEqual(self.direct(kind,b"[]\n").values[0].normalized_value,[])

    def test_bad_json_duplicate_keys_nan_nested_and_bounds_rejected(self):
        cases=(
          b"{}\n",b"null\n",b"{} []\n",b"[\n",b'[{"ifindex":1,"ifindex":2,"ifname":"lo"}]\n',
          b'[{"ifindex":1,"ifname":"lo","addr_info":{}}]\n',
          b'[{"ifindex":true,"ifname":"lo"}]\n',
          b'[{"ifname":"lo"}]\n',b'[{"ifindex":1,"ifname":""}]\n',
          b'[{"ifindex":1,"ifname":"lo","metric":NaN}]\n',
          b'[{"ifindex":1,"ifname":"lo","nested":[[[[[[[[[[[[0]]]]]]]]]]]]}]\n',
          b'[{"ifindex":1,"ifname":"l\\u0000o"}]\n',
          b'[{"ifindex":1,"ifname":"lo","x":"\xff"}]\n',
          b'[{"ifindex":1,"ifname":"lo","x":"'+b"x"*5000+b'"}]\n',
          b'[{"ifindex":1,"ifname":"lo","x":"'+b"x"*(1024*1024)+b'"}]\n',
        )
        for raw in cases:
            with self.subTest(raw=raw[:50]),self.assertRaises(SourceParseError):
                self.direct("addr",raw)
        for raw in (b'[{}]\n',b'[{"dst":true}]\n',b'[{"metric":NaN}]\n',
                    b'[{"dst":"default","dst":"other"}]\n',b'[1]\n'):
            with self.subTest(raw=raw),self.assertRaises(SourceParseError):
                self.direct("route",raw)

    def test_direct_wrong_or_missing_attribution_rejected(self):
        for args in (
          dict(source_stream="stderr",source_command=COMMANDS[0]),
          dict(source_stream=None,source_command=COMMANDS[0]),
          dict(source_stream="stdout",source_command=None),
          dict(source_stream="stdout",source_command="ip addr show"),
          dict(source_stream="stdout",source_command=COMMANDS[1],source_path="/proc/net/route"),
          dict(source_stream="stdout",source_command=COMMANDS[0],source_target="eth0"),
        ):
            with self.subTest(args=args),self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-23",ADDR,**args)

    def test_swapped_command_and_json_family_rejected(self):
        with self.assertRaises(SourceParseError):
            self.direct("route",ADDR)
        with self.assertRaises(SourceParseError):
            self.direct("addr",ROUTE)

    def test_canonical_two_attempts_and_source_original_lineage(self):
        folder,run,arts=self.make(items={
          "01":(("call0001-stdout",ADDR),("call0001-stderr",b"diagnostic\n")),
          "02":(("call0002-stdout",ROUTE),("call0002-stderr",b"diagnostic 2\n"))})
        m=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),m)
        obs=json.loads((folder/"private/system.json").read_text())["observations"]
        for path,eid in (("network.ip.local_addresses.reported",arts[0].evidence_id),
                         ("network.ip.local_routes.reported",arts[2].evidence_id)):
            matches=[v for v in obs if v["datum_path"]==path]
            self.assertEqual(len(matches),1)
            self.assertEqual(matches[0]["evidence_refs"],[eid])
        for a in arts:
            self.assertEqual(hashlib.sha256((folder/a.private_relative_path).read_bytes()).hexdigest(),a.sha256)
        st=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        self.assertEqual([(x["status"],x["reason_code"]) for x in st],
                         [("COMPLETE","OK"),("COMPLETE","OK")])

    def test_source_partial_exit_retains_status_and_actual_code(self):
        folder,run,_=self.make(variants={"02":dict(outcome="PARTIAL",reason="EXIT_NONZERO",
                                               attrs=dict(exit_code=2))})
        build_canonical(folder,run)
        st=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        self.assertEqual(st[1]["reason_code"],"SOURCE_INCOMPLETE")
        self.assertIn("exit_code=2",st[1]["detail"])

    def test_parser_failed_when_captured_unknown_json_without_inventing_route(self):
        folder,run,arts=self.make(items={"01":(("call0001-stdout",ADDR),),
                                        "02":(("call0002-stdout",b'{"unexpected":"json"}\n'),)})
        build_canonical(folder,run)
        st=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        self.assertEqual(st[1]["reason_code"],"PARSE_FAILED")
        self.assertEqual((folder/arts[-1].private_relative_path).read_bytes(),b'{"unexpected":"json"}\n')

    def test_bad_attempt_ordinal_invocation_target_path_and_capture_contradictions(self):
        cases=(
          dict(variants={"01":dict(attrs=dict(invocation=COMMANDS[1]))}),
          dict(variants={"02":dict(attrs=dict(invocation=COMMANDS[0]))}),
          dict(items={"01":(("call0002-stdout",ADDR),)}),
          dict(items={"02":(("call0001-stdout",ROUTE),)}),
          dict(items={"03":(("call0003-stdout",ADDR),)}),
          dict(variants={"01":dict(attrs=dict(source_paths=("/proc/net/route",)))}),
          dict(variants={"01":dict(attrs=dict(target="lo"))}),
          dict(variants={"01":dict(attrs=dict(exit_code=3))}),
          dict(variants={"01":dict(attrs=dict(exit_code=None))}),
          dict(variants={"01":dict(attrs=dict(timed_out=True))}),
          dict(variants={"01":dict(attrs=dict(capture_limited=True))}),
          dict(tamper=0),
          dict(items={"01":(("call0001-stderr",b"warning\n"),)}),
        )
        for kw in cases:
            with self.subTest(kw=kw):
                folder,run,_=self.make(**kw)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)
                self.assertFalse((folder/"private/session_manifest.json").exists())

if __name__=="__main__":
    unittest.main()
