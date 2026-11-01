import unittest
from lbt_g5.passive_worker import collect
from lbt_g5.local_space import eligible_mounts
class CompletionSmoke(unittest.TestCase):
    def test_only_known_sources(self):
        with self.assertRaises(ValueError):
            list(collect('SRC-13'))
    def test_remote_mount_excluded(self):
        self.assertEqual(eligible_mounts('41 25 0:35 / /mnt/net rw - nfs x:y rw'),())

    def test_d0_attempt_ceiling_counts_unavailable_attributes(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            dev=root/"hwmon0"
            dev.mkdir()
            for i in (1,2,3):
                (dev/("temp%d_input"%i)).symlink_to("/never/allowed")
            records=list(collect("SRC-25",roots={"SRC-25":str(root)},
                                 max_bytes=4096,max_entries=2))
            self.assertEqual(sum("error" in x for x in records),2)
            self.assertEqual(records[-1]["attempted"],2)
            self.assertTrue(records[-1]["limited"])

    def test_efi_terminal_marker(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            efi=Path(tmp)/"efi"
            efi.mkdir()
            records=list(collect("SRC-03",roots={"SRC-03":str(efi)}))
            self.assertEqual(records[-1]["entries"],1)
            self.assertTrue(records[-1]["end"])

    def test_private_error_identifies_failed_attribute(self):
        import json
        from lbt_g5.passive import _transport_decode
        from lbt_g5.safety import initial_source_policies
        policy=next(p for p in initial_source_policies() if p.source_id=="SRC-25")
        message={"path":"/sys/class/hwmon/hwmon0/temp2_label",
                 "error":"FileNotFoundError"}
        end={"end":True,"entries":0,"bytes":0,"limited":False}
        transport=(json.dumps(message)+"\n"+json.dumps(end)+"\n").encode()
        records,errors,terminal,acquired,unavailable=_transport_decode(transport,policy)
        self.assertEqual(records,[])
        self.assertIn("FileNotFoundError:/sys/class/hwmon/hwmon0/temp2_label",errors)
        self.assertEqual(acquired,0)
        self.assertTrue(terminal["end"])

    def test_optional_missing_vs_unexpected_error(self):
        import errno
        from lbt_g5.passive_worker import _optional_absence
        missing=FileNotFoundError(errno.ENOENT,"not present")
        fault=OSError(errno.EIO,"failed")
        self.assertTrue(_optional_absence("SRC-07","/sys/devices/system/cpu/cpu0/online",missing))
        self.assertTrue(_optional_absence("SRC-12","/sys/class/block/loop0/device/model",missing))
        self.assertTrue(_optional_absence("SRC-26","/sys/class/power_supply/AC/capacity",missing))
        self.assertFalse(_optional_absence("SRC-26","/sys/class/power_supply/AC/type",missing))
        self.assertFalse(_optional_absence("SRC-25","/sys/class/hwmon/hwmon0/temp1_input",fault))
        self.assertTrue(_optional_absence("SRC-22","/sys/class/net/eno1/speed",
                                         OSError(errno.EOPNOTSUPP,"unsupported")))

    def test_optional_transport_is_not_source_failure(self):
        import json
        from lbt_g5.passive import _transport_decode
        from lbt_g5.safety import initial_source_policies
        policy=next(p for p in initial_source_policies() if p.source_id=="SRC-26")
        msg={"path":"/sys/class/power_supply/AC/capacity","error":"FileNotFoundError",
             "errno":2,"unavailable":True}
        end={"end":True,"entries":0,"bytes":0,"limited":False}
        raw=(json.dumps(msg)+"\n"+json.dumps(end)+"\n").encode()
        acquired,errors,terminal,size,unavailable=_transport_decode(raw,policy)
        self.assertEqual(errors,[])
        self.assertEqual(len(unavailable),1)
        self.assertEqual(size,0)
        self.assertEqual(acquired,[])
        self.assertTrue(terminal["end"])

    def test_live_usb_overlay_eligible_but_remote_still_excluded(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            source="\n".join((
                "5 1 0:1 / / rw - overlay /cow rw",
                "6 1 8:2 / "+tmp+" rw - vfat /dev/sdb1 rw",
                "7 1 0:2 / /mnt/net rw - cifs remote rw"))
            mounts=eligible_mounts(source)
            self.assertIn("/",mounts)
            self.assertIn(tmp,mounts)
            self.assertNotIn("/mnt/net",mounts)

    def test_exact_one_file_entry_limit_is_not_truncation(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"mountinfo"
            path.write_bytes(b"42 1 0:50 / / rw - overlay /cow rw\n")
            records=list(collect("SRC-14",roots={"SRC-14":str(path)},
                                 max_bytes=16*1024*1024,max_entries=1))
            self.assertEqual(len(records),2)
            self.assertEqual(records[-1]["entries"],1)
            self.assertEqual(records[-1]["attempted"],1)
            self.assertFalse(records[-1]["limited"])

    def test_actual_extra_candidate_triggers_entry_cap(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"sys_vendor").write_text("Fixture Vendor")
            records=list(collect("SRC-04",roots={"SRC-04":str(root)},
                                 max_bytes=4*1024*1024,max_entries=1))
            self.assertEqual(records[-1]["attempted"],1)
            self.assertTrue(records[-1]["limited"])

    def test_other_single_file_sources_do_not_falsely_truncate(self):
        import tempfile
        from pathlib import Path
        for sid in ("SRC-02","SRC-06","SRC-08","SRC-09","SRC-10","SRC-16"):
            with self.subTest(sid=sid),tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/"observed"
                path.write_bytes(b"observed\n")
                records=list(collect(sid,roots={sid:str(path)},
                                     max_bytes=1024,max_entries=1))
                self.assertEqual(records[-1]["attempted"],1)
                self.assertFalse(records[-1]["limited"])
