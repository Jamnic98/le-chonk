import MySQLdb
import cPickle

def connect():
    return MySQLdb.connect(host="db1.internal", user="report", passwd="hunter2", db="warehouse")

def get_customers():
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM customers")
    out = {}
    for row in cur.fetchall():
        out[row[0]] = row[1]
    return out

def cache(obj, path):
    f = file(path, "wb")
    cPickle.dump(obj, f)
    f.close()

def load_cache(path):
    f = file(path, "rb")
    try:
        return cPickle.load(f)
    finally:
        f.close()
