/*

priiloader/preloader 0.30 - A tool which allows to change the default boot up sequence on the Wii console
Executable Loader - Loads any executable who has been loaded into memory

Copyright (C) 2008-2019  crediar

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


*/

#include <ogc/machine/processor.h>
#include <gctypes.h>
#include "executables.h"

void DCFlushRange(void *startaddress,u32 len);
void ICInvalidateRange(void* addr, u32 size);
void _memcpy(void* dst, void* src, u32 len);
void _memset(void* src, u32 data, u32 len);
u32 _loadApplication(void* binary, void* parameter);
u32 _loadSystemMenu(void* binary, void* parameter, u32 parameterCount);

//this --MUST-- be the first code in this file.
//when run, we will jump to addr 0 of the compiled code. if this is on top, this will be the code run
void _start(void* binary, void* parameter, u32 parameterCount, u8 isSystemMenu)
{
	if(binary == NULL || (parameter == NULL && parameterCount > 0))
		return;

	u32 ep = (isSystemMenu)?_loadSystemMenu(binary,parameter,parameterCount):_loadApplication(binary,parameter);
	if(!ep)
		return;

	if(isSystemMenu)
	{
		if(ep != 0x80003400)
			return;

		mtmsr(mfmsr() & ~0x8000);
		mtmsr(mfmsr() | 0x2002);
	}
	else
	{
		void	(*entrypoint)();
		entrypoint = (void (*)())(ep);
		entrypoint();
	}
	return;
}

u32 _loadApplication(void* binary, void* parameter)
{
	Elf32_Ehdr *ElfHdr = (Elf32_Ehdr *)binary;
	struct __argv *args = (struct __argv *)parameter;

	if( ElfHdr->e_ident[EI_MAG0] == 0x7F &&
		ElfHdr->e_ident[EI_MAG1] == 'E' &&
		ElfHdr->e_ident[EI_MAG2] == 'L' &&
		ElfHdr->e_ident[EI_MAG3] == 'F' )
	{
		if( (ElfHdr->e_entry | 0x80000000) < 0x80003400 && (ElfHdr->e_entry | 0x80000000) >= 0x817FFEFF )
		{
			return 0;
		}

		for( s32 i=0; i < ElfHdr->e_phnum; ++i )
		{
			Elf32_Phdr* phdr;
			phdr = binary + (ElfHdr->e_phoff + sizeof( Elf32_Phdr ) * i);
			ICInvalidateRange ((void*)(phdr->p_vaddr | 0x80000000),phdr->p_filesz);
			if(phdr->p_type != PT_LOAD )
				continue;
			_memcpy((void*)(phdr->p_vaddr | 0x80000000), binary + phdr->p_offset , phdr->p_filesz);
		}

		//according to dhewg the section headers are totally un-needed (infact, they break a few elf loading)
		//however, checking for the type does the trick to make them work :)
		for( s32 i=0; i < ElfHdr->e_shnum; ++i )
		{
			Elf32_Shdr *shdr;
			shdr = binary + (ElfHdr->e_shoff + sizeof( Elf32_Shdr ) * i);

			//useless check
			//if( shdr->sh_type == SHT_NULL )
			//	continue;

			if (shdr->sh_type != SHT_NOBITS)
				continue;
				
			_memcpy((void*)(shdr->sh_addr | 0x80000000), binary + shdr->sh_offset,shdr->sh_size);
			DCFlushRange((void*)(shdr->sh_addr | 0x80000000),shdr->sh_size);
		}
		return (ElfHdr->e_entry | 0x80000000);	
	}
	else
	{
		dolhdr *dolfile;
		dolfile = (dolhdr *)binary;

		//entrypoint & BSS checking
		if( (dolfile->entrypoint | 0x80000000) < 0x80003400 || (dolfile->entrypoint | 0x80000000) >= 0x817FFEFF )
		{
			return 0;
		}
		if( dolfile->addressBSS >= 0x90000000 )
		{
			//BSS is in mem2 which means its better to reload ios & then load app. i dont really get it but thats what tantric said
			//currently unused cause this is done for wiimc. however reloading ios also looses ahbprot/dvd access...
			
			//place IOS reload here
		}

		for (s8 i = 0; i < 7; i++) {
			if ((!dolfile->sizeText[i]) || (dolfile->addressText[i] < 0x100)) 
				continue;
			_memcpy ((void *) dolfile->addressText[i],binary+dolfile->offsetText[i],dolfile->sizeText[i]);
			DCFlushRange ((void *) dolfile->addressText[i], dolfile->sizeText[i]);
			ICInvalidateRange((void *) dolfile->addressText[i],dolfile->sizeText[i]);
		}

		for (s8 i = 0; i < 11; i++) {
			if ((!dolfile->sizeData[i]) || (dolfile->offsetData[i] < 0x100)) continue;
			_memcpy ((void *) dolfile->addressData[i],binary+dolfile->offsetData[i],dolfile->sizeData[i]);
			DCFlushRange((void *) dolfile->offsetData[i],dolfile->sizeData[i]);
		}

		if( 
			( dolfile->addressBSS + dolfile->sizeBSS < 0x80F00000 ||(dolfile->addressBSS > 0x81500000 && dolfile->addressBSS + dolfile->sizeBSS < 0x817FFFFF) ) &&
			dolfile->addressBSS > 0x80003400 )
		{
			_memset ((void *) dolfile->addressBSS, 0, dolfile->sizeBSS);
			DCFlushRange((void *) dolfile->addressBSS, dolfile->sizeBSS);
		}
		if (args != NULL && args->argvMagic == ARGV_MAGIC)
        {
			void* new_argv = (void*)(dolfile->entrypoint + 8);
			_memcpy(new_argv, args, sizeof(struct __argv));
			DCFlushRange(new_argv, sizeof(struct __argv));
        }
		return(dolfile->entrypoint | 0x80000000);
	}	
	 return 0;
}

u32 _loadSystemMenu(void* binary, void* parameter, u32 parameterCount)
{

	//add check to see if entrypoint == 0x00003400 here
	//if( boot_hdr->entrypoint != 0x3400 )
	
	/* offset patches will go here*/

	return _loadApplication(binary,NULL);
}

//copy of libogc & gcc, this is to have the loader as small as possible
//this is very bad practice , but this source is meant to be copied to memory and ran as stand alone code
//to be able to do this, and be asured the first code is _start, this code has a copy of the required functions
void _memcpy(void* dst, void* src, u32 len)
{
	u8 *d = dst;
	const u8 *s = src;
	while (len--)
		*d++ = *s++;
	return;
}
void _memset(void* dst, u32 data, u32 len)
{
	u8 *ptr = dst;
	while (len-- > 0)
		*ptr++ = data;
	return;
}

asm(R"(.globl DCFlushRange
DCFlushRange:
	cmplwi 4, 0   # zero or negative size?
	blelr
	clrlwi. 5, 3, 27  # check for lower bits set in address
	beq 1f
	addi 4, 4, 0x20 
1:
	addi 4, 4, 0x1f
	srwi 4, 4, 5
	mtctr 4
2:
	dcbf 0, 3
	addi 3, 3, 0x20
	bdnz 2b
	sc
	blr)");

asm(R"(.globl ICInvalidateRange
ICInvalidateRange:
	cmplwi 4, 0   # zero or negative size?
	blelr
	clrlwi. 5, 3, 27  # check for lower bits set in address
	beq 1f
	addi 4, 4, 0x20 
1:
	addi 4, 4, 0x1f
	srwi 4, 4, 5
	mtctr 4
2:
	icbi 0, 3
	addi 3, 3, 0x20
	bdnz 2b
	sync
	isync
	blr)");