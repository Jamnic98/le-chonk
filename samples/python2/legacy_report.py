#!/usr/bin/env python2
import sys, os, csv, urllib2, ConfigParser, cPickle

def load_config(path):
    cp = ConfigParser.ConfigParser()
    cp.read(path)
    return cp

def fetch_rates(url):
    resp = urllib2.urlopen(url)
    return resp.read()

def summarize(rows, out):
    print "Writing report to", out
    f = open(out, "wb")
    w = csv.writer(f)
    for r in rows:
        if r.has_key("amount"):
            w.writerow([r["name"], r["amount"]])
    f.close()
    print "Done. %d rows" % len(rows)

def main():
    cfg = load_config("app.ini")
    base = cfg.get("main", "endpoint")
    data = fetch_rates(base + "/rates.csv")
    rows = cPickle.loads(data)
    total = 0
    for r in rows:
        try:
            total += r["amount"] / 2
        except KeyError, e:
            print >>sys.stderr, "missing", e
    print "Total:", total
    if total > 100:
        raise ValueError, "too big"
    summarize(rows, "report.csv")

if __name__ == "__main__":
    main()
