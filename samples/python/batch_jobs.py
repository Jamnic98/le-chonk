import os
import pickle
import subprocess
import hashlib
import yaml
import requests

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def run_user_job(spec):
    return eval(spec["code"])


def load_cache(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def run_shell(cmd):
    subprocess.call("chmod " + cmd, shell=True)
    os.system("echo " + cmd)


def find_user(conn, name):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()


def make_token(user):
    return hashlib.md5((user + "salt").encode()).hexdigest()


def fetch(url):
    return requests.get(url, verify=False)


def load_cfg(path):
    with open(path) as f:
        return yaml.load(f)
