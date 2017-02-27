import subprocess

subprocess.call('py md5check.py -h', shell=True)
pid = subprocess.Popen(args=['cmd.exe', '--command=py']).pid
