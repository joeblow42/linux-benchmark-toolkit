"""G5-01 fixtures: metadata-only IC-01/G4-07 initial catalog checks."""
import unittest
from lbt_g5.catalog import (
    CatalogError, INITIAL_COLLECTOR_IDS, INITIAL_SOURCE_ROWS,
    initial_catalog, validate_catalog,
)

class InitialCatalogContract(unittest.TestCase):
    def test_approved_initial_ids(self):
        cols,src=initial_catalog()
        self.assertEqual((len(cols),len(src)),(13,28))
        self.assertEqual({s.source_id for s in src},{f"SRC-{n:02d}" for n in range(1,29)})

    def test_approved_o1_sources(self):
        _,src=initial_catalog()
        self.assertEqual({s.source_id for s in src if s.authorization_class=="O1"},
                         {"SRC-13","SRC-18","SRC-21"})

    def test_ownership_separation(self):
        _,src=initial_catalog()
        owners={s.source_id:s.collector_id for s in src}
        self.assertEqual((owners["SRC-11"],owners["SRC-14"]),("COL-BLOCK","COL-FS"))
        self.assertEqual((owners["SRC-19"],owners["SRC-21"]),("COL-GPU","COL-VAAPI"))

    def test_duplicate_source_refused(self):
        with self.assertRaises(CatalogError):
            validate_catalog(INITIAL_COLLECTOR_IDS,INITIAL_SOURCE_ROWS+(INITIAL_SOURCE_ROWS[0],))

    def test_unknown_owner_refused(self):
        with self.assertRaises(CatalogError):
            validate_catalog(INITIAL_COLLECTOR_IDS,
                             INITIAL_SOURCE_ROWS+(("SRC-29","COL-UNKNOWN","D0","LOCAL_API"),))

    def test_prohibited_class_refused(self):
        for flag in ("X","root",None,1):
            with self.subTest(flag=flag),self.assertRaises(CatalogError):
                validate_catalog(INITIAL_COLLECTOR_IDS,(("SRC-01","COL-OS",flag,"LOCAL_API"),))

    def test_registry_has_no_fixed_collector_ceiling(self):
        cols,src=validate_catalog(
            INITIAL_COLLECTOR_IDS+("COL-FUTURE",),
            INITIAL_SOURCE_ROWS+(("SRC-29","COL-FUTURE","D0","FUTURE_OPERATION"),))
        self.assertEqual((len(cols),len(src)),(14,29))

    def test_no_source_execution_on_metadata_lookup(self):
        from unittest.mock import patch
        with patch("subprocess.run",side_effect=AssertionError("source invoked")):
            _,src=initial_catalog()
        self.assertEqual(len(src),28)

if __name__=="__main__":
    unittest.main()
