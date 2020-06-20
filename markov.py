"""
Python 的多行注释是 docstring。

[Python]
for i in range(len(passwords)):
    password = passwords[i]

[C++]
for (const string &password : passwords) {
    cout << password << endl;
}
"""


"""
1. 打开字典文件，遍历每个已知的密码
2. 统计情况
3. 输出统计结果

开始符号：' ' 结束符号：'\n'
"""

import json
import sys
import crypt
import datetime
import heapq

ORDER = 4
MAX_PASSWORD_LENGTH = 6

SYMBOL_SET = '0123456789' + 'abcdefghijklmnopqrstuvwxyz' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + '!#$'
SYMBOL_BEGIN = ''
SYMBOL_END = '\n'

freq, total = dict(), dict()


def statistics():
    global freq, total

    with open("dictionary.txt", "r") as file:
        passwords = file.read().split('\n')

        for password in passwords:
            password = password.strip()
            if len(password) == 0:
                continue

            password = password + SYMBOL_END
            head = SYMBOL_BEGIN

            # abc123
            # a | Begin
            # b | a
            # c | ab
            # 1 | abc
            # 2 | abc1
            # 3 | bc12
            # Terminal | c123

            # Pr(3 | bc12)
            #   == freq["bc12"]["3"] / total["bc12"]
            # freq["bc12"]["3"]: 出现“bc123”的次数
            # total["bc12"]:     出现“bc12X”（X为任意字符）的次数

            # for password in ["123", "456", "789"]:
            #     password <- "123", "456", "789"
            #     for char in "123":
            #         char <- "1", "2", "3"

            for char in password:
                # if len(head) == ORDER + 1:
                head = head[-ORDER:]

                # Pr(char | head) := freq[head][char] / total[head]
                # total[head] :=
                # freq[head][char]: 当前字符为 char，且前几个字符为 head 出现的次数。
                if head not in freq:
                    freq[head] = dict()
                if char not in freq[head]:
                    freq[head][char] = 1
                else:
                    freq[head][char] = freq[head][char] + 1
                total[head] = total[head] + 1 if head in total else 1
                # total[head] = sum(list(freq[head].items()))

                head = head + char

        for key in freq.keys():
            freq[key] = {k: v for k, v in sorted(freq[key].items(), key=lambda item: item[1], reverse=True)}
            for char in freq[key].keys():
                freq[key][char] = freq[key][char] / total[key]

# 经典的 guess
# a
#   ab ac ad ae ...
#    aba abb abc ...
#    aca acb acd ...
# b
#   ba bb bc bd
#
# 可能的改进：使用优先队列（排序因子：马尔科夫概率）
# heapq <- 优先队列 in python

def guess():
    # 小顶堆
    # 较小的元素先出堆。
    heap = [(-1, '')] # [(密码的概率, 密码)]

    while len(heap) > 0:
        probability, password = heapq.heappop(heap)
        if password.endswith('\n'):  # （注意越界！）password[-1] == '\n'; password[password.size() - 1] == '\n'
            yield password[:-1], -probability
            continue

        tail = password[-ORDER:]  # 取末尾的 4 个字符
        if tail not in freq:
            continue

        # P(xxxxabcdy) = P(xxxxabcd) * P(y | xxxxabcd)
        if len(password) == MAX_PASSWORD_LENGTH:
            if '\n' in freq[tail]:
                candidates = ['\n']
            else:
                candidates = []
            # candidates = ['\n'] if '\n' in freq[tail] else []
        else:
            candidates = freq[tail].keys()

        for char in candidates:
            heapq.heappush(heap, (probability * freq[tail][char], password + char))


def bruteforce():
        with open("shadow", "r") as shadow_file:
            lines = shadow_file.readlines()

        for line in lines:
            sections = line.split(':')
            username = sections[0]
            secret = sections[1]
            secret_sections = secret.split('$')

            if len(secret_sections) == 4:
                print("Cracking password for user " + username + ":")

                salt = secret_sections[2]
                hashed_passwd = secret_sections[3]

                count = 0
                begin_time = datetime.datetime.now()
                for password, probability in guess():
                    count = count + 1

                    if crypt.crypt(password, '$'.join(secret_sections[:3]) + salt) == secret:
                        print('Found password for', username, 'after trial of', count, 'passwords.')
                        print('\t', 'password:', password, 'probability:', probability)
                        break

                    if count % 10000 == 0:
                        print('\t', datetime.datetime.now() - begin_time, "has tried", count, "passwords.", \
                            "current:", password, "probability:", probability)
                else:
                    print("Fail to find password for " + username + "!")


if __name__ == "__main__":
    statistics()
    # print(json.dumps(freq, indent=2))
    bruteforce()
