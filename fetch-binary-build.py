import urllib2
import os


pieces = """
Security.hdrs.tar.gz
Security.root.tar.gz
SecurityTokend.hdrs.tar.gz
SecurityTokend.root.tar.gz
libsecurity_cdsa_client.hdrs.tar.gz
libsecurity_cdsa_client.root.tar.gz
libsecurity_cdsa_utilities.hdrs.tar.gz
libsecurity_cdsa_utilities.root.tar.gz
libsecurity_utilities.root.tar.gz
libsecurity_utilities.hdrs.tar.gz
"""

pieces = pieces.rstrip().lstrip().split("\n")
snowleopard = ["10A432", "10B504", "10C540", "10D573"]
snowleopard.sort()
snowleopard.reverse()

leopard = ["9A581", "9B18", "9C31", "9D34", "9E17", "9F33", "9G55", "9J61", "9L30"]
leopard.sort()
leopard.reverse()
ROOT = "http://src.macosforge.org/Roots/"


try:
		os.mkdir("build-snowleopard")
except OSError:
		pass
		
os.chdir("build-snowleopard")
for release in snowleopard:
		for piece in pieces:
				url = "%s%s/%s" % (ROOT, release, piece)
				filename = piece
				if not os.path.exists(filename):
						try:
								print "Trying %s" % (url)
								req = urllib2.urlopen(url)
								print "Fetching %s" % (url)
								f = open(filename, "w")
								f.write(req.read())
								f.close()
						except urllib2.HTTPError as problem:
								if problem.getcode() != 404:
										raise
