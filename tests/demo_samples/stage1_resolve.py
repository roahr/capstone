"""
Demo Case 1: SAST Stage Resolution (Stage 1)

These are clear, well-known vulnerabilities with short taint paths.
Tree-sitter matches them with high confidence -> low uncertainty -> resolve at SAST.

Expected: All findings resolve at Stage 1 (no GNN/LLM needed).
This demonstrates cascade EFFICIENCY -- simple vulns handled cheaply.
"""
import os
import pickle

# CWE-78: OS Command Injection (direct, 1-hop)
user_cmd = input("Enter command: ")
os.system(user_cmd)

# CWE-502: Unsafe Deserialization (direct, 1-hop)
with open("data.pkl", "rb") as f:
    obj = pickle.loads(f.read())

# CWE-95: Code Injection via eval (direct, 1-hop)
expr = input("Calculate: ")
result = eval(expr)
print(result)
