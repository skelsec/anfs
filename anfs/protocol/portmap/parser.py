

res = {}
with open('programs.md', 'r') as f:
    for line in f:
        if line.startswith('#'):
            continue
        try:
            pid, name = line[38:].split('    ')
            pid = int(pid)
            name = name.strip()
            if name.find(' ') != -1:
                name = name.replace(' ', '/')
            res[pid] = name
        except:
            print(line[34:])
            input(line)
            continue

print(repr(res))