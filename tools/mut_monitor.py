import subprocess, time
end = time.time() + 600
while time.time() < end:
    def p(ip):
        return subprocess.run(['ping','-c','1','-W','1',ip], capture_output=True).returncode == 0
    print(time.strftime('%H:%M:%S'), '.200=', 'UP' if p('192.168.1.200') else 'down',
          '.1=', 'UP' if p('192.168.1.1') else 'down', flush=True)
    time.sleep(2)
