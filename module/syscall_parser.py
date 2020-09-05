from db_connect import get_data_bbdd
import json

def count_syscalls(param):
    counter = {}
    results = get_data_bbdd(".\\db.sqlite3", "name, analisis", 0, "web_muestra", param)
    # Añadir syscalls
    for result in results:
        data = json.loads(result[1])
        counter[result[0]] = {}
        for key in data.keys():
            for syscall in data[key]["syscalls"]:
                if syscall not in counter[result[0]].keys():
                    counter[result[0]][syscall] = 0
                else:
                    counter[result[0]][syscall] += 1


    return counter


