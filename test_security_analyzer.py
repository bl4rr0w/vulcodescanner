import unittest
import os
from security_analyzer import detect_insecure_imports, detect_sql_injection, detect_xss, read_file, run_bandit

class TestSecurityAnalyzer(unittest.TestCase):
    def test_detect_insecure_imports(self):
        content = "import os\nos.system('ls')\neval('2 + 2')"
        result = detect_insecure_imports(content)
        self.assertEqual(result, ["os.system", "eval"])

    def test_detect_sql_injection(self):
        content = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        result = detect_sql_injection(content)
        self.assertTrue(any("execute" in r for r in result))

    def test_detect_xss(self):
        content = "<script>alert('XSS')</script>"
        result = detect_xss(content)
        self.assertTrue(any("<script>" in r for r in result))

    def test_read_file(self):
        with open("test_file.py", "w") as f:
            f.write("print('Hello, World!')")
        content = read_file("test_file.py")
        self.assertEqual(content, "print('Hello, World!')")
        os.remove("test_file.py")

    def test_run_bandit(self):
        with open("test_bandit.py", "w") as f:
            f.write("import pickle\npickle.loads(user_input)")
        result = run_bandit("test_bandit.py")
        self.assertTrue(any("pickle" in issue for issue in result))
        os.remove("test_bandit.py")

if __name__ == "__main__":
    unittest.main()