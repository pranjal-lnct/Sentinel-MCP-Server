import unittest
import os
import shutil
import tempfile
from sentinel.services.code_context import CodebaseSummarizer

class TestCodebaseSummarizer(unittest.TestCase):
    
    def setUp(self):
        self.summarizer = CodebaseSummarizer()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_summarize_structure(self):
        # Create dummy structure
        os.makedirs(os.path.join(self.test_dir, "src", "api"))
        with open(os.path.join(self.test_dir, "Dockerfile"), "w") as f:
            f.write("FROM python:3.9")
        with open(os.path.join(self.test_dir, "src", "main.py"), "w") as f:
            f.write("print('hello')")
            
        summary = self.summarizer.summarize(self.test_dir)
        
        tree = summary["file_tree"]
        self.assertIn("Dockerfile", tree)
        self.assertIn("src/", tree)
        self.assertIn("main.py", tree)

    def test_read_key_files(self):
        # Create key file
        with open(os.path.join(self.test_dir, "requirements.txt"), "w") as f:
            f.write("flask==2.0.0")
            
        # Create ignored file
        with open(os.path.join(self.test_dir, "random.txt"), "w") as f:
            f.write("ignore me")
            
        summary = self.summarizer.summarize(self.test_dir)
        
        key_files = summary["key_files"]
        self.assertIn("requirements.txt", key_files)
        self.assertEqual(key_files["requirements.txt"], "flask==2.0.0")
        self.assertNotIn("random.txt", key_files)

if __name__ == "__main__":
    unittest.main()
