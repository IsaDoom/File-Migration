import shutil
from unittest.mock import patch
from secure_organizer import process_file, Manifest

def test_file_corruption_quarantines_file(tmp_path):
    # 1. Setup temporary directories
    intake = tmp_path / "incoming"
    dest = tmp_path / "organized"
    quarantine = dest / "_quarantine"
    
    intake.mkdir()
    dest.mkdir()
    
    # 2. Create a dummy file
    test_file = intake / "important_drawing.dwg"
    test_file.write_text("Original safe content")
    
    # 3. Setup the manifest
    manifest_path = dest / ".integrity" / "manifest.jsonl"
    manifest = Manifest(manifest_path)
    
    # 4. Create a malicious copy function
    original_copy = shutil.copy2
    def corrupted_copy(src, dst):
        original_copy(src, dst)
        with open(dst, "a") as f:
            f.write("corrupted_byte")
            
    # 5. Run the function while intercepting shutil.copy2
    with patch("secure_organizer.shutil.copy2", side_effect=corrupted_copy):
        process_file(test_file, dest, quarantine, manifest)
        
    # 6. Assert security outcomes
    organized_file = dest / "cad_drawings" / "important_drawing.dwg"
    quarantined_file = quarantine / "important_drawing.dwg"
    
    assert not organized_file.exists()
    assert quarantined_file.exists()
    assert not test_file.exists()
    
    log_entries = manifest.read_all()
    assert len(log_entries) == 1
    assert log_entries[0]["status"] == "MISMATCH_QUARANTINED"