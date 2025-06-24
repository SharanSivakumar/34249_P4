import time
import subprocess

thrift_port = 9090

def update_global_tick():
    while True:
        now_tick = int(time.time()) % 100000 
        cmd = f'echo "register_write global_tick 0 {now_tick}" | simple_switch_CLI --thrift-port {thrift_port}'
        try:
            subprocess.call(cmd, shell=True)
        except Exception as e:
            print("Error updating tick:", e)
        time.sleep(1) 

if __name__ == "__main__":
    print("Starting global tick updater...")
    update_global_tick()
