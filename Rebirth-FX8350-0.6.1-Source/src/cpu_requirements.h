#pragma once
#include <intrin.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>

// A conservative supported-host baseline, not a proven minimum requirement.
// The v6 payload replaces AVX2/BMI2, leaving other game instructions in place.
struct CpuFacts {
    bool ssse3=false,sse41=false,sse42=false,popcnt=false,fma3=false,f16c=false;
    bool xsave=false,osxsave=false,avx=false,bmi1=false,lzcnt=false,ymm_state=false;
};
static CpuFacts ReadCpuFacts(){
    CpuFacts facts;
    int leaf[4]={};__cpuidex(leaf,0,0);const unsigned maximum=static_cast<unsigned>(leaf[0]);
    if(maximum>=1){
        __cpuidex(leaf,1,0);const unsigned bits=static_cast<unsigned>(leaf[2]);
        facts.ssse3=(bits&(1u<<9))!=0;facts.fma3=(bits&(1u<<12))!=0;
        facts.sse41=(bits&(1u<<19))!=0;facts.sse42=(bits&(1u<<20))!=0;
        facts.popcnt=(bits&(1u<<23))!=0;facts.xsave=(bits&(1u<<26))!=0;
        facts.osxsave=(bits&(1u<<27))!=0;facts.avx=(bits&(1u<<28))!=0;
        facts.f16c=(bits&(1u<<29))!=0;
        // XGETBV itself must not execute before XSAVE/OSXSAVE are established.
        if(facts.xsave&&facts.osxsave)facts.ymm_state=(_xgetbv(0)&6)==6;
    }
    if(maximum>=7){__cpuidex(leaf,7,0);facts.bmi1=(static_cast<unsigned>(leaf[1])&(1u<<3))!=0;}
    __cpuidex(leaf,static_cast<int>(0x80000000u),0);
    if(static_cast<unsigned>(leaf[0])>=0x80000001u){
        __cpuidex(leaf,static_cast<int>(0x80000001u),0);facts.lzcnt=(static_cast<unsigned>(leaf[2])&(1u<<5))!=0;
    }
    return facts;
}
static std::vector<std::string> MissingCpuFeatures(const CpuFacts& facts){
    std::vector<std::string> missing;
    if(!facts.avx)missing.push_back("AVX");
    if(!facts.xsave)missing.push_back("XSAVE");
    if(!facts.osxsave)missing.push_back("OSXSAVE (Windows AVX support)");
    if(!facts.ymm_state)missing.push_back("Windows XMM/YMM state support (XCR0 bits 1 and 2)");
    if(!facts.ssse3)missing.push_back("SSSE3");
    if(!facts.sse41)missing.push_back("SSE4.1");
    if(!facts.sse42)missing.push_back("SSE4.2");
    if(!facts.popcnt)missing.push_back("POPCNT");
    if(!facts.fma3)missing.push_back("FMA3");
    if(!facts.f16c)missing.push_back("F16C");
    if(!facts.bmi1)missing.push_back("BMI1");
    if(!facts.lzcnt)missing.push_back("LZCNT");
    return missing;
}
static std::string MissingCpuMessage(const CpuFacts& facts){
    auto missing=MissingCpuFeatures(facts);std::ostringstream message;
    message<<"This CPU/Windows configuration is outside this mod's supported baseline. Missing: ";
    for(size_t i=0;i<missing.size();++i){if(i)message<<", ";message<<missing[i];}
    message<<". No files were changed. AVX2 and BMI2 are not required by this check.";
    return message.str();
}
static bool PrintCpuCheck(const CpuFacts& facts){
    const auto missing=MissingCpuFeatures(facts);
    std::cout<<"CPU prerequisite check: "<<(missing.empty()?"PASS":"FAIL")<<"\n";
    std::cout<<"Required baseline: AVX, XSAVE/OSXSAVE with Windows XMM/YMM state, SSSE3, SSE4.1, SSE4.2, POPCNT, FMA3, F16C, BMI1, LZCNT.\n";
    for(const auto& feature:missing)std::cout<<"Missing: "<<feature<<"\n";
    std::cout<<"AVX2/BMI2 are not required. This conservative check is not a guarantee of game compatibility or performance.\n";
    return missing.empty();
}
