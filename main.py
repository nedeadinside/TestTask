import os
import re
import sys
import time
import joblib
import inquirer
import pandas as pd

from statistics import median
from collections import defaultdict

import numpy as np
import scapy.all as scapy


def offline_sniffing(mac=scapy.Ether().src):
    """
    Функция offline_sniffer была создана для сбора статистики из уже имеющегося файла формата .pcap.
    Я решил просто добавить данную функцию например для создания оцифрованных данных для НС, собранных посредством
    какой-либо утилиты, например тот же WireShark. В параметрах у него mac адрес устройства, для того,
     чтобы можно было запускать скрипт с другой машины.
    """
    sniffer_data = scapy.sniff(offline='output.pcap')
    try:
        pkt_time = sniffer_data[0].time
    except IndexError:
        print('Файл пуст!')
        sys.exit(-1)

    pack_times.append(pkt_time)
    dumps_time.append(pkt_time)

    for pkt in sniffer_data:
        data_selection(pkt, mac)


def online_sniffing(start, timeout, store=True, endpoint=24 * 60 * 60):
    """
    Функция online_sniffing была создана для сбора статистики онлайн, а также для анализа трафика, она принимает на вход
    параметры.start - время запуска сниффера
    timeout - время после которого сниффер будет останавливаться и перезапускаться. Нужен для сбора статистики онлайн,
    чтобы не перегружать store
    store - параметр, который отвечает за хранение данных сниффера, принимает True или False
    endpoint - время при достижении которого программа прекратит работу, по умолчанию 24 часа.
    """
    while time.time() - start <= endpoint:
        try:
            if store:
                sniffer_data = scapy.sniff(store=store, prn=data_selection, timeout=timeout)
                scapy.wrpcap('output.pcap', sniffer_data, append=True)
            else:
                scapy.sniff(store=store, prn=data_selection, timeout=timeout)
        except KeyboardInterrupt:
            print('Сниффер остановлен')
            break


def data_selection(pkt, mac=scapy.Ether().src):
    """
    Функция data_selection вызывается на каждый пакет собранный сниффером, параметр по умолчанию сам пакет, из функции
    offline_sniffing она вызывается с дополнительным параметром mac адреса.

    В функции происходит проверка, которая фильтрует только пакеты приходящие на сервер. Данные из пакета записываются
    в словарь посредством вызова функции write_to_dict().

    Также по истечении времени, которое установлено dump_const вызывается функция data_collect,
     по умолчанию это происходит каждые 5 секунд
    """
    if pkt.dst == mac:
        if pkt.haslayer(scapy.Raw):
            write_to_dict(pkt.time, pkt[scapy.Raw].load)
        else:
            write_to_dict(pkt.time)

        if pkt.time - dumps_time[-1] >= dump_const:
            data_collect(pkt.time - dumps_time[-1])
            dumps_time.append(pkt.time)


def write_to_dict(curr_time, curr_data=b''):
    """
    Функция write_to_dict принимает на вход время пакета, а также его содержимое(если оно есть),
     далее собираются параметры, которые записываются в глобальный словарь packet_stats.
    Параметры являются оцифрованной пакетной статистикой.
    """
    data_size = len(curr_data)
    delta = curr_time - pack_times[-1]

    if delta != 0:
        delta_time.append(curr_time - pack_times[-1])

    pack_times.append(curr_time)

    packet_stats['sum_data'] += data_size
    packet_stats['max_packet'] = max(data_size, packet_stats['max_packet'])
    packet_stats['packet_counter'] += 1


def model_predict(sum_data, max_pkt, pkt_count, avg_pkt, flow_speed, pkt_speed, delta_med):
    """
    Функция model_predict вызывает подгруженную модель НС, а также выводит информацию пакетной статистики,
    если обнаруживает аномальную активность. После чего записывает ее в файл.
    """
    X = np.array([[sum_data, max_pkt, pkt_count, avg_pkt, flow_speed, pkt_speed, delta_med]])
    y = int(model.predict(X)[0])
    if y:
        stat = f'Time: {time.ctime(int(time.time()))}, Sum_data: {sum_data} Max_pkt: {max_pkt}, Pkt_count: {pkt_count}' + \
               f' Avg_pkt: {avg_pkt}, Flow_speed: {flow_speed}, Pkt_speed: {pkt_speed}, Delta_med: {delta_med}\n'

        print('ALARM ALARM ALARM ALARM ALARM ALARM ALARM ALARM ALARM ALARM \n' + stat)

        with open('attack_stat.txt', 'a') as f:
            f.write(stat)


def data_collect(sec):
    """
    Функция data_collect собирает оцифрованные данные, сохраняет их в переменную data_frame, после чего очищает лист,
     который хранит значения межпакетных интервалов, и словарь. Также из нее вызывается функция model_predict,
     если пользователь выбрал модель НС.
    """
    if sec == 0:
        return -1

    sum_data = packet_stats['sum_data']
    max_pkt = packet_stats['max_packet']
    pkt_count = packet_stats['packet_counter']
    avg_pkt = sum_data / pkt_count if pkt_count != 0 else 1
    flow_speed = float(sum_data / sec)
    pkt_speed = float(pkt_count / sec)
    delta_med = float(median(delta_time))
    delta_min = float(min(delta_time))

    data_frame.append({
        'sum_data': sum_data,
        'max_pkt': max_pkt,
        'pkt_count': pkt_count,
        'avg_pkt': avg_pkt,
        'flow_speed': flow_speed,
        'pkt_speed': pkt_speed,
        'delta_min': delta_min,
        'delta_med': delta_med
    })

    if flag:
        model_predict(sum_data, max_pkt, pkt_count, avg_pkt, flow_speed, pkt_speed, delta_med)

    packet_stats.clear()
    delta_time.clear()


def dialog(ans: str, msg: str, choices: list) -> str:
    message = [inquirer.List(f'{ans}', message=msg, choices=choices)]
    return inquirer.prompt(message)[f'{ans}']


def store_pcap_param():
    f_msg = "Сохранять пакетную статистику в .pcap файл?"
    f_choice = dialog('choice', f_msg, choices=['Да', 'Нет'])

    if f_choice == 'Да':
        store = True

        msg_1 = '\nВведите в секундах интервал, с которым статистика будет записываться в .pcap файл:\n>>> '
        timeout = ''

        while not timeout.isnumeric():
            timeout = input(msg_1)
        timeout = int(timeout)
    else:
        store = False
        timeout = 600

    end_time = ''
    msg_1_2 = '\nВведите период сбора статистики сбора статистики(в часах):\n>>> '

    while not end_time.isnumeric():
        end_time = input(msg_1_2)

    end_time = int(end_time) * 60 * 60  # Пишу 60 60, а не 3600, потому что хочу
    return store, end_time, timeout


def main():
    while True:
        lst_hello = ['Сбор онлайн трафика', 'Анализ онлайн трафика', 'Сбор трафика из .pcap файла', 'Выход']
        choice = dialog('choice', 'Выберите пункт меню', choices=lst_hello)

        if choice == lst_hello[0]:
            store, end_time, timeout = store_pcap_param()

            print('Запуск!')
            online_sniffing(time.time(), endpoint=end_time, store=store, timeout=timeout)

            input('Работа завершена, нажмите любую клавишу.')
            time.sleep(2)
            break

        elif choice == lst_hello[1]:
            store, end_time, timeout = store_pcap_param()

            files = [i for i in os.listdir() if i[-4:] == '.pkl']
            if len(files) != 0:

                file = dialog('file_choice', 'Выберете название файла: ', choices=files)
                global model
                model = joblib.load(file)

                global flag
                flag = True

                online_sniffing(start=time.time(), store=store, endpoint=end_time, timeout=timeout)
                try:
                    if os.stat('attack_stat.txt').st_size != 0:
                        with open('attack_stat.txt', 'r') as file:
                            lst = file.readlines()

                        for i in lst:
                            print(i.rstrip())
                    else:
                        print('Атак не зафиксировано. \n')
                except FileNotFoundError:
                    print('Атак не зафиксировано. \n')

        elif choice == lst_hello[2]:
            t_choice = dialog('mac_choice',
                              msg='Ввести MAC адрес вручную или использовать адрес текущего устройства?',
                              choices=['Вручную', 'Это устройство'])

            if t_choice == 'Вручную':
                p = re.compile(r'(?:[0-9a-fA-F]:?){12}')
                f = False

                while not f:
                    mac = re.search(p, input('Введите MAC адрес:\n>>> '))
                    if mac is not None:
                        mac = mac.group(0)
                        f = True
                    else:
                        print('Ошибка!')
                        continue
                offline_sniffing(mac)

            else:
                offline_sniffing()

        else:
            print("Выход из программы.")
            sys.exit(0)


if __name__ == '__main__':
    packet_stats = defaultdict(int)

    start_time = time.time()
    dump_const = 5

    data_frame = []
    delta_time = []
    pack_times = [start_time]
    dumps_time = [start_time]

    flag = False
    main()

    df = pd.DataFrame(data_frame)
    df.to_csv('Data.csv', index=False)
