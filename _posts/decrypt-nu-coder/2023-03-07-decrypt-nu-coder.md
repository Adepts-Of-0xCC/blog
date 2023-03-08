---
title: "Beating an old PHP source code protector"
date: 2023-03-07 00:00:00 +00:00
modified: 2023-03-07 00:00:00 +00:00
tags: [red team, research, php, nu-coder, X-C3LL]
description: Article describing how to decode/decrypt source code protected with Nu-Coder
image:
---

Dear Fell**owl**ship, today's homily is about our last fight against an ancient artifact called Nu-Coder, The PHP Protector. Please, take a seat and listen to the story.


# Prayers at the foot of the Altar a.k.a. disclaimer
*This research was done because a co-worker asked me for help when he was looking for vulnerabilities in a EOL product. Internet only offered to him pay-to-decrypt solutions and with so many files it was not an option. Thank you for giving me this weekend challenge!*

# Pilot Episode: Ocarina of Time
Something obvious to anybody who worked as developer with any interpreted language is that once you share your code, you are fucked. As the code is in plain text, it's trivial to everyone read/understand/modify it without your consent. Well, It also could be applied to compiled files as long as you have enough coffee and time. But you understand what I mean.

Because of this reason, source code protections started to populate. Some examples in PHP ecosystem could be IonCube, Zend Guard or Nu-Coder. The latter was a popular option back in the 2000's when the main PHP versions were PHP 4 and PHP 5, but today the project is abandoned. The last supported PHP version is 5.3, so you can imagine the rest.

As the project is not continued and the last supported version is **old**, I believe that sharing this article will not cause any harm and can be useful to others who want to dig in this piece from the past.

In general source code protectors in PHP works as loaders that uncompress and/or decrypt bytecode generated directly from the sources. This bytecode contains the opcodes that are interpreted by Zend Engine VM. In some cases the protector can also hook the Zend Engine in order to *reinterpret* the opcodes, adding functionalities or directly building it's own VM as IonCube does.

In the case of Nu-Coder the method used to protect the code was not a problem. The biggest problem to retrieve original source code was that **PHP 5.3 is too old and building stuff is a pain the ass.** So, bring your ocarina of time and play the song to go to the past!

# Episode 1: Get it the DeLorean, Marty
Before even starting to analyze this source protector I needed to setup an environment. And trust me, trying to compile PHP 5.3 in a modern OS is like eating a cactus.

The first thing you need to know is that by default it needs a patch to fix some issue related to XML parsing, so if you don't patch the source code you can not compile it because the gcc will scream. Luckily someone published a patch:

```bash
curl -o php-5.3.1.patch https://mail.gnome.org/archives/xml/2012-August/txtbgxGXAvz4N.txt
cd php(...)
patch -p0 -b <../php-5.3.1.patch
```
Oh, you will think it is all. Now you can enjoy your shiny and new compiled PHP. Nopes. You have to modify the Makefile to add the `-fcommon` flag.

I know reading it seems easy. Yeah, and it does. Once you hit your head so hard for hours because you can not find why you can not compile this damn old PHP version.


# Episode 2: It's not Piracy when it's Legacy
Once I had a working environment I needed to get a copy of Nu-Coder. Luckily you can download a trial from the last version from the official website. The problem is...
```bash
➜  nucoder ./nu-coder.bk -s test.php
Fatal error: Nu-coder license is invalid or corrupted or issued for a different product.
In order to use nucoder you need to obtain license from NuSphere Corp. (www.nusphere.com)
and save it in to "./nu-coder.lic" file

```
...I need a trial license. And to obtain it I have to send a mail. So it's a dead end, as the product is discontinued.

At least PHPExpress (the loader that Nu-Coder uses) can be used without any license. And you would think "Oh, then just reverse the code". Well, that could be an option if I know RE. Nopes, I want to follow the path of least resistance and analyze it dynamically. And to accomplish that I need to bypass this license check.

A bit of good old patching was enough:
```c
[0x00401850]> s 0x405526
[0x00405526]> pd 3
        ┌─< 0x00405526      0f8462040000   je 0x40598e
        │   0x0040552c      488bb4247011.  mov rsi, qword [rsp + 0x1170]
        │   0x00405534      4885f6         test rsi, rsi
[0x00405526]> oo+
[0x00405526]> wai jne 0x40598e
INFO: Written 6 byte(s) ( jne 0x40598e) = wx 0f8562040000 @ 0x00405526
[0x00401850]> s 0x4059a2
[0x004059a2]> pd 3
       ┌──< 0x004059a2      7507           jne 0x4059ab
       │╎   0x004059a4      31db           xor ebx, ebx
       │└─< 0x004059a6      e9a6fbffff     jmp 0x405551
[0x004059a2]> wai je 0x4059ab
INFO: Written 2 byte(s) ( je 0x4059ab) = wx 7407 @ 0x004059a2
```

Well I also used a small hook (because with one of the patches you end reaching a buffer that is freed and then reused in a `strdup()`; you can choose between hooking strdup or "noping" the `free(buffer)`):
```bash
➜  nucoder LD_PRELOAD=/home/vagrant/research/nucoder/test.so ./nu-coder.patched2 -s test.php
Fatal error: Nu-coder license is invalid or corrupted or issued for a different product.
In order to use nucoder you need to obtain license from NuSphere Corp. (www.nusphere.com)
and save it in to "./nu-coder.lic" file

[*] Hook: aberration remedied
-/home/vagrant/research/nucoder/test.php
0 files encoded, 0 files copied, 1 errors, 0:01 elapsed
```

Result (ignore the "1 errors"):
```php
➜  nucoder cat test.php.enc
<?php

//    Produced with Nu-Coder 3.1.0 Evaluation Version,
//    http://www.nusphere.com/
//    [THIS MESSAGE WILL NOT APPEAR IN THE PURCHASED VERSION OF NUCODER]

?><?php
if(!extension_loaded('Php Express')){$__['os']=strtoupper(substr(PHP_OS,0,3));$__['ver']=strtoupper(substr(PHP_VERSION,0,3));$__['ext']=($__['os']=='WIN')?'.dll':'.so';$__['nam']='phpexpress-php-'.$__['ver'].$__['ext'];$__['edr']=realpath(ini_get('extension_dir'));$__['sdr']=getcwd();if($__['os']=='WIN'){$__['idr']=str_replace('\\','/',$__['edr']);$__['sdr']=str_replace('\\','/',$__['sdr']);if((strlen($__['idr'])>2)&&($__['idr'][1]==':'))$__['idr']=substr($__['idr'],2);if((strlen($__['sdr'])>2)&&($__['sdr'][1]==':'))$__['sdr']=substr($__['sdr'],2);}else{$__['idr']=$__['edr'];}$__['rd']=str_repeat('/..',substr_count($__['idr'],'/')).$__['sdr'].'/';$__['i']=strlen($__['rd']);while(true){$__['i']=strrpos($__['rd'],'/');if($__['i']!==false){$__['rd']=substr($__['rd'],0,$__['i']);$__['lp']=$__['rd'].'/phpexpress/'.$__['nam'];if(file_exists($__['edr'].$__['lp'])){$__['nam']=$__['lp'];break;}$__['lp']=$__['rd'].'/'.$__['nam'];if(file_exists($__['edr'].$__['lp'])){$__['nam']=$__['lp'];break;}}else break;}@dl($__['nam']);if(function_exists('__pe_dl_init')){return __pe_dl_init();}else{echo('<h2>Error:</h2><br>file <i>'.__FILE__."</i> requires Php Express loader to be installed by the web site administrator.\n");exit(2);}}die('File '.__FILE__." is corrupted.\n");
?>
NUCODER&0ˎ��"6������!x
```


# Episode 3: Hooked on a Feeling
Once I can generate encoded samples I can start to work on how to decode/decrypt Nu-Coder. Searching a bit on the official(~~ly dead~~) forum I could find this quote from the developer:

> We carefully explored whole the idea of implementing our own proprietary VM for php, considered pros and cons, and finally decided not to follow it(...)
> If the package is encoded by Nu-Coder with license protection and license itself is not available to the engineer (intruder), he will have to crack AES128 first.(...)

So if I understand it correctly the only protection it brings is applied to the whole bytecode itself. But if it doesn't modify the Zend Engine, then it means at some point the real opcodes must be provided to Zend Engine. My hypothesis is that we can recover the clean opcodes at `zend_execute` level, as it would be the logical entry point. This function receives an `zend_op_array` struct that contains an array with all the opcodes.

```c
struct _zend_op_array {

/* Common elements */

zend_uchar type;

const char *function_name;

zend_class_entry *scope;

zend_uint fn_flags;

union _zend_function *prototype;

zend_uint num_args;

zend_uint required_num_args;

zend_arg_info *arg_info;

/* END of common elements */

zend_uint *refcount;

zend_op *opcodes;

zend_uint last;

zend_compiled_variable *vars;

int last_var;

zend_uint T;

zend_brk_cont_element *brk_cont_array;

int last_brk_cont;

zend_try_catch_element *try_catch_array;

int last_try_catch;

/* static variables support */

HashTable *static_variables;

zend_uint this_var;

const char *filename;

zend_uint line_start;

zend_uint line_end;

const char *doc_comment;

zend_uint doc_comment_len;

zend_uint early_binding; /* the linked list of delayed declarations */

zend_literal *literals;

int last_literal;

void **run_time_cache;

int last_cache_slot;

void *reserved[ZEND_MAX_RESERVED_RESOURCES];

};
```

If our hypothesis is correct, if we put a breakpoint on this function we will able to retrieve the real opcodes. Let's see!
```c
pwndbg> b *dlopen
Breakpoint 1 at 0x904e0
pwndbg> r -d "extension=/home/vagrant/research/nucoder/phpexpress-php-5.3.so" -d "extension=/usr/lib/php/5.3/lib/php/extensions/no-debug-non-zts-20090626/parsekit.so" ../index.php
//(...)
Breakpoint 1, ___dlopen (file=0x7ffff59c3448 "/home/vagrant/research/nucoder/phpexpress-php-5.3.so", mode=mode@entry=265) at ./dlfcn/dlopen.c:77
77	./dlfcn/dlopen.c: No such file or directory.
pwndbg> b *zend_execute
Breakpoint 2 at 0x555555815bb0: file /home/vagrant/research/nucoder/php-5.3.1/Zend/zend_vm_execute.h, line 40.
pwndbg> c
Continuing.

Breakpoint 2, execute (op_array=0x555555d66098) at /home/vagrant/research/nucoder/php-5.3.1/Zend/zend_vm_execute.h:40
40	{
pwndbg> print op_array->opcodes[0]->handler
$2 = (opcode_handler_t) 0x55555583d030 <ZEND_FETCH_R_SPEC_CONST_HANDLER>
pwndbg> print op_array->opcodes[0]->op1
$3 = {
  op_type = 1,
  u = {
    constant = {
      value = {
        lval = 93825000694400,
        dval = 4.6355709564134141e-310,
        str = {
          val = 0x555555d66280 "_SERVER",
          len = 7
        },
        ht = 0x555555d66280,
        obj = {
          handle = 1440113280,
          handlers = 0x7
        }
      },
      refcount__gc = 2,
      type = 6 '\006',
      is_ref__gc = 1 '\001'
    },
    var = 1440113280,
    opline_num = 1440113280,
    op_array = 0x555555d66280,
    jmp_addr = 0x555555d66280,
    EA = {
      var = 1440113280,
      type = 21845
    }
  }
}

pwndbg> print op_array->opcodes[1]->handler
$4 = (opcode_handler_t) 0x555555856b50 <ZEND_FETCH_DIM_R_SPEC_VAR_CONST_HANDLER>
pwndbg> print op_array->opcodes[1]->op2
$6 = {
  op_type = 1,
  u = {
    constant = {
      value = {
        lval = 93825000694432,
        dval = 4.6355709564149952e-310,
        str = {
          val = 0x555555d662a0 "DOCUMENT_ROOT",
          len = 13
        },
        ht = 0x555555d662a0,
        obj = {
          handle = 1440113312,
          handlers = 0xd
        }
      },
      refcount__gc = 2,
      type = 6 '\006',
      is_ref__gc = 1 '\001'
    },
    var = 1440113312,
    opline_num = 1440113312,
    op_array = 0x555555d662a0,
    jmp_addr = 0x555555d662a0,
    EA = {
      var = 1440113312,
      type = 21845
    }
  }
}
pwndbg> print op_array->opcodes[2]->handler
$8 = (opcode_handler_t) 0x55555582e650 <ZEND_CONCAT_SPEC_VAR_CONST_HANDLER>
pwndbg> print op_array->opcodes[2]->op2
$7 = {
  op_type = 1,
  u = {
    constant = {
      value = {
        lval = 93825000694464,
        dval = 4.6355709564165762e-310,
        str = {
          val = 0x555555d662c0 "/include/func.php",
          len = 17
        },
        ht = 0x555555d662c0,
        obj = {
          handle = 1440113344,
          handlers = 0x11
        }
      },
      refcount__gc = 2,
      type = 6 '\006',
      is_ref__gc = 1 '\001'
    },
    var = 1440113344,
    opline_num = 1440113344,
    op_array = 0x555555d662c0,
    jmp_addr = 0x555555d662c0,
    EA = {
      var = 1440113344,
      type = 21845
    }
  }
}
pwndbg> print op_array->opcodes[3]->handler
$9 = (opcode_handler_t) 0x5555558200f0 <ZEND_INCLUDE_OR_EVAL_SPEC_TMP_HANDLER>
```

Jackpot!

It is doing a concatenation between two constants and then an include/require! something like `require($_SERVER['DOCUMENT_ROOT' . '/include/func.php')`, and **that is exactly what the first line of our code does!!!!!**.

Once I confirmed that I could recover the opcodes directly I tried to compile the classic tools I used in CTFs: VLD, phpdebug, opdumper, etc. I wasted hours of my time trying to compile them in my environment and for PHP 5.3. I gave up that day: I didn't want to build a parser. Luckily the next day I found this project called [**pecl-php-parserkit**](https://github.com/php/pecl-php-parsekit/blob/master/parsekit.c) and it was everything I was needing: an opcode parser for PHP 5. And easy to mod!

So I added this function to parserkit:

```c
static void xc3ll_hook(zend_op_array *ops){
    zend_op *op;
	int i;
	long flags = PHP_PARSEKIT_EXTENDED_VALUE;
    zval *return_value;
    MAKE_STD_ZVAL(return_value);
	array_init(return_value);

	for (op = ops->opcodes, i = 0; op && i < ops->size; op++, i++) {
		char *opline, *result, *op1, *op2;
		int opline_len, freeit = 0;

		if (php_parsekit_parse_node_simple(&result, ops, &(op->result), ops TSRMLS_CC)) {
			freeit |= 1;
		}
		if (php_parsekit_parse_node_simple(&op1, ops, &(op->op1), ops TSRMLS_CC)) {
			freeit |= 2;
		}
		if (php_parsekit_parse_node_simple(&op2, ops, &(op->op2), ops TSRMLS_CC)) {
			freeit |= 4;
		}

		opline_len = spprintf(&opline, 0, "%s %s %s %s",
			php_parsekit_define_name_ex(op->opcode, php_parsekit_opcode_names, &flags, PHP_PARSEKIT_OPCODE_UNKNOWN),
			result, op1, op2);
        FILE *fp = fopen("log.txt", "a");
        fprintf(fp, "%s\n", opline);
        fclose(fp);
		if (freeit & 1) efree(result);
		if (freeit & 2) efree(op1);
		if (freeit & 4) efree(op2);

		add_next_index_stringl(return_value, opline, opline_len, 0);
	}
    //php_var_dump(&return_value, 1);
}
```
It receives a pointer to a `zend_op_array` and parse the opcodes, saving the "meaning" in a file called `log.txt`. Nothing fancy, but it did the work. Now I only need to load it and call this function with the pointer that `zend_execute` would use:
```c
pwndbg> b *zend_execute
Breakpoint 2 at 0x555555815bb0: file /home/vagrant/research/nucoder/php-5.3.1/Zend/zend_vm_execute.h, line 40.
pwndbg> c
Continuing.

Breakpoint 2, execute (op_array=0x555555d66098) at /home/vagrant/research/nucoder/php-5.3.1/Zend/zend_vm_execute.h:40
pwndbg> print (void) xc3ll_hook(op_array)
$12 = void
pwndbg> !
➜  pecl-php-parsekit git:(master) ✗ head log.txt
ZEND_FETCH_R T(0) '_SERVER' UNUSED
ZEND_FETCH_DIM_R T(1) T(0) 'DOCUMENT_ROOT'
ZEND_CONCAT T(2) T(1) '/include/func.php...'
ZEND_INCLUDE_OR_EVAL T(3) T(2) 0x8
ZEND_FETCH_R T(4) '_SERVER' UNUSED
ZEND_FETCH_DIM_R T(5) T(4) 'DOCUMENT_ROOT'
ZEND_CONCAT T(6) T(5) '/include/init.php...'
ZEND_INCLUDE_OR_EVAL T(7) T(6) 0x8
ZEND_FETCH_R T(8) '_SERVER' UNUSED
ZEND_FETCH_DIM_R T(9) T(8) 'DOCUMENT_ROOT'
```

Nu-Coder is defeated! Now we have the original code (well, we need to parse the output to rebuild it, but is simple).

# EoF

Of course this is only a shortened version of what happened this weekend.

We hope you enjoyed this reading! Feel free to give us feedback at our twitter [@AdeptsOf0xCC](https://twitter.com/AdeptsOf0xCC).
