# MakeProcCrit

A tool that can make a process into a critical process.

*(If such process is later closed, or terminated, it will cause a Blue-Screen-of-Death.)*

This is also a POC project for my blog post:

## "Native Functions To The Rescue - Part 1"
### "[How to make a critical process that can crash Windows if it is closed](https://dennisbabkin.com/blog/?i=AAA11F00)."

*It covers the technical details of how to give a running process (or a thread) a critical status, or to remove it.*

-------------------------
## Download
You can download the binary file to run the MakeProcCrit tool [here](https://dennisbabkin.com/php/downloads/MakeProcCrit.zip).

## Operation
Make sure to run the tool as an administrator. It should give you the list of available command line options:

![Screenshot1](https://github.com/dennisbabkin/MakeProcCrit/blob/main/Screenshots/scr1.png)

Then, if you want to make a process critical, say, all running Notepads, you would do:

`MakeProcCrit.exe 1 notepad`

or, you can do it by a PID:

`MakeProcCrit.exe 1 1234`

![Screenshot2](https://github.com/dennisbabkin/MakeProcCrit/blob/main/Screenshots/scr2.png)

If the operation succeeds, and you try to terminate it, say, with a Task Manager, you'd get this warning:

![Screenshot3](https://github.com/dennisbabkin/MakeProcCrit/blob/main/Screenshots/scr3.png)

Alternatively, if you close that instance of Notepad, you'd crash the operating system:

![Screenshot3](https://github.com/dennisbabkin/MakeProcCrit/blob/main/Screenshots/scr4.png?raw=true)

Finally, to remove the critical status from the poor Notepad (or from any other process), do:

`MakeProcCrit.exe 0 notepad`

For more details, please [read the blog post](https://dennisbabkin.com/blog/?i=AAA11F00).

