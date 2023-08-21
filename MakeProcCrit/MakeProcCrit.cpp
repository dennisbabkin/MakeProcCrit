// This is a Proof-of-Concept (POC) project that demonstrates
// how to make any process into a "critical process" and to revert it back.
//
// Copyright (c) 2023, by dennisbabkin.com
//
//
// This project is used in the following blog post:
//
//  "Native Functions To The Rescue - Part 1"
//  "How to make a critical process that can crash Windows if it is closed."
//
//   https://dennisbabkin.com/blog/?i=AAA11F00
//

#include "CMain.h"





int wmain(int argc, WCHAR* argv[])
{
    return CMain::processCmdLine(argc, argv);
}


