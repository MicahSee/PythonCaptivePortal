from flask import Flask, request, render_template, redirect, url_for
import iptc
import re
from threading import Timer
from config import log, log_time

app = Flask(__name__)

def clear_log():
    open(log, 'w').close()
    start_timer()
    return


def start_timer():
    timer = Timer(log_time, clear_log)
    timer.start()
    return


@app.route('/')
def login():
    return render_template('captiveportal.html')


@app.route('/post', methods=["POST"])
def post():
    if request.form['username'] == 'admin' and request.form['password'] == 'admin':
        client_ip = request.remote_addr
        ip_regex = r"SRC={}".format(client_ip)

        with open(log) as log_file:
            log_file = log_file.readlines()

        for line in log_file:
            mo = re.search(ip_regex, line)
            if mo:
                matched_line = line
                break

        mo = re.search(r"(([a-f0-9]+:){6})(?P<src_mac>(([a-f0-9]+:){5})[a-f0-9]+)", matched_line)
        src_mac = mo.group('src_mac')

        rule = iptc.Rule()
        match_mac = iptc.Match(rule, "mac")
        match_mac.mac_source = src_mac
        rule.add_match(match_mac)
        rule.target = iptc.Target(rule, "ACCEPT")
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain._rule(rule)

        # eventually add a timer for mac address sessions
        return redirect('http://www.google.com')

    else:
        return redirect(url_for('login'))


if __name__ == "__main__":
    start_timer()
    try:
    	app.run(host='0.0.0.0', ssl_context=('cert.pem','key.pem'))
    except KeyboardInterrupt:
	print 'Ctrl^C pressed'
    # run startup python program that add prerequsite iptables rules
    # and other things in README
