// This is a manual attempt at decompiling the overworld item balls into more readable c++ code
// It contains some comments that explain certain things
// It's recommended to read the disasembly example file first



int sysreq(int id, ...) {
    // ...
    return something();
}

int something() {
    // ...
    return something();
}

void moveData(int source, int dest, int length) {
    // An opcode that moves more than just one variable from one address to another, 
    //   here used for copying the movement instructions to local variables
    // ...
    return;
}

void halt(int exit_value, int param) {
    // using 12 as param is a sleep command (actually used in this script)
    return;
}

int func41(int p12_itemid) {
    // Interesting numbers used in this and other functions, should be researched
    int v4_unk = 0;
    int v8_unk = sysreq(30, p12_itemid);
    if (v8_unk != 0) {
        return 0x50029;
    }
    int v12_unk = sysreq(20, p12_itemid);
    switch (v12_unk) {
        case 2:
            v4_unk = 0x50007;
            break;
        case 3:
            v4_unk = 0x50009;
            break;
        case 4:
            v4_unk = 0x50003;
            break;
        default:
            v4_unk = 0x50002;
            break;
    }
    return v4_unk;
}

int func43() {
    sysreq(5, 0x60000);
    return 0;
}

int func26(int p12_msgid, int p16_unk, int p20_unk) {
    func1(p12_msgid, 0, -1, 11, 20, p16_unk, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, p20_unk);
    return 0;
}

int func45_msgTMHM(int p12_itemid) {
    func25_wordplayer(0);
    sysreq(15, 1, p12_itemid, 1);
    sysreq(16, 2, p12_itemid);
    func26(6, 170, 0);
    return 0;
}

int func47_msgfound(int p12_itemid, int p16_unk) {
    func25_wordplayer(0);
    sysreq(15, 1, p12_itemid, 1);
    func27(5, 170, p16_unk, 0);
    return 0;
}

int func48(int p12_unk) {
    while (sysreq(7, p12_unk) == 0) {
        func6_wait(1);
    }
    sysreq(8);
    return 0;
}

int func25_wordplayer(int p12_bufferid) {
    return sysreq(1, 1, p12_bufferid, 0);
}

int func37(int p12_unk) {
    while (sysreq(14, p12_unk) == 0) {
        func6_wait(1);
    }
    return 0;
}

int func34_actionexec(int p12_mdlid, int p16_addr_action, int p20_cmdlen) {
    sysreq(11, p12_mdlid);
    loop: for (int v4_unk = 0; v4_unk < p20_cmdlen; v4_unk += 3) {
        if (*(p16_addr_action + (v4_unk << 2)) == 65535) {
            break loop;
        }
        sysreq(
            12, 
            *(p16_addr_action + (v4_unk << 2)), 
            *(p16_addr_action + ((v4_unk + 1) << 2)), 
            *(p16_addr_action + ((v4_unk + 2) << 2))
        );
    }
    sysreq(13);
    return 0;
}

int func35(int p12_unk) {
    if (0 >= p12_unk) {
        return 0;
    }
    for (int v4_unk = 0; v4_unk < p12_unk; v4_unk++) {
        func6_wait(1);
    }
    return 0;
}

int func50_canpickup(int p12_itemid, int p16_count, int p20_unk, int p24_flag, int p28_unk, int p32_unk) {
    sysreq(17, p12_itemid, p16_count);
    func28();
    int v4_unk = sysreq(18);
    int pri, alt; // Some hacky jumping stuff?
    if (p28_unk != 0) {
        if (v4_unk != 0 && v4_unk != 2 && v4_unk != 10) {
            pri = 0;
        } else {
            pri = 1;
        }
        if (pri != 0) {
            pri = 1;
        }
    } else {
        pri = 0;
    }
    if (pri != 0) {
        int v8_unk, v12_unk, v16_unk, v20_unk, v24_unk, v28_action;
        moveData(0, &v28_action, 24);
        v24_unk = p20_unk;
        v12_unk = p20_unk;
        func34_actionexec(255, &v28_action, 6);
        func35(13);
        if (p24_flag != -1) {
            sysreq(19, p24_flag);
        }
        func37(255);
        // vars from this block are deallocated here
    } else {
        if (p24_flag != -1) {
            sysreq(19, p24_flag);
        }
    }
    func25_wordplayer(0);
    sysreq(15, 1, p12_itemid, p16_count);
    int v8_itempocket = sysreq(20, p12_itemid);
    sysreq(21, 2, v8_itempocket);
    func27(9, 170, p32_unk, 0);
    sysreq(22);
    func39(0);
    sysreq(23, 0x8010, 1);
    return 0;
}

int func39(int p12_unk) {
    sysreq(6, p12_unk);
    return 0;
}

int func6_wait(int p12_unk) {
    sysreq(0, p12_unk);
    halt(0, 12);
    return 0;
}

int func8_keywait() {
    while (sysreq(10) == 0) {
        func6_wait(1);
    }
    return 0;
}

// Yes, this function (and script command) has 19 params
int func1(
    int p12_msgid, int p16, int p20, int p24, int p28, 
    int p32, int p36, int p40, int p44, int p48, 
    int p52, int p56, int p60, int p64, int p68, 
    int p72, int p76, int p80, int p84
) {
    sysreq(
        9, 
        int p12_msgid, int p16, int p20, int p24, int p28, 
        int p32, int p36, int p40, int p44, int p48, 
        int p52, int p56, int p60, int p64, int p68, 
        int p72, int p76, int p80, int p84
    );
    if (p84 & 0x10000 == 0) {
        func8_keywait();
    }
    return 0;
}

int func27(int p12_msgid, int p16_unk, int p20_unk, int p24_unk) {
    func1(p12_msgid, 0, -1, 11, 20, p16_unk, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, p20_unk, p24_unk);
    return 0;
}

int func28() {
    sysreq(2);
    sysreq(3);
    sysreq(4);
    sysreq(5, 393216);
    return 0;
}

int func52_bagfull(int p12_itemid, int p16_count, int p20_unk) {
    func28();
    sysreq(15, 0, p12_itemid, p16_count);
    // func27 is one of two functions that call func1, and thereby the message display command
    // I assumed 170 to be the text file number, but this script's text is actually in text file 142, so good question what the 170 does
    func27(7, 170, p20_unk, 0);
    sysreq(22);
    func39(0);
    // 0x8010 is a known local return var from at least Gen 5 (I haven't done any scripting in gens 1-4, so maybe even earlier?)
    sysreq(23, 0x8010, 0);
    return 0;
}

int func60_wait(int p12_itemid, int p16_count, int p20_unk, int p24_flag) {
    int v4_flag = p24_flag;
    if (v4_flag != -1) {
        // The flag loaded from the data section is only a relative flag to the overworld item flags section
        // ...which begins at exactly 1306
        // This is the line that made reverse engineering everything else from this script even possible
        v4_flag += 1306;
    }
    sysreq(24);
    int v8_istmhm = 0;
    int v12_canpickup = 0;
    int v16_unk = func41(p12_itemid);
    v8_istmhm = sysreq(25, p12_itemid);
    v12_canpickup = sysreq(26, p12_itemid, 1);
    int v20_unk = sysreq(27, 255);
    sysreq(28, v16_unk);
    if (v12_canpickup != 0 && v4_flag != -1) {
        sysreq(29, v4_flag);
    }
    func43();
    if (v8_istmhm != 0) {
        func45_msgTMHM(p12_itemid);
    } else {
        func47_msgfound(p12_itemid, 0);
    }
    func48(v16_unk);
    if (v12_canpickup != 0) {
        func50_canpickup(p12_itemid, p16_count, v20_unk, v4_flag, p20_unk, 0);
    } else {
        func52_bagfull(p12_itemid, p16_count, 0);
    }
    return 0;
}

int main() {
    // ... Some very weird stuff happening here
    // Don't even try to make sense of the opcodes in this main function
    // It's all gibberish that only gives you headaches
    int v4_num;
    int v8_itemid;
    int v12_count;
    int v16_flag;
    // ...
    func60_wait(v8_itemid, v12_count, 1, v16_flag);
    return 0;
}
