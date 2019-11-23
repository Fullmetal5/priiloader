/*

priiloader/preloader 0.30 - A tool which allows to change the default boot up sequence on the Wii console

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

#include <stdio.h>
#include <stdlib.h>
#include <gccore.h>
#include <string.h>
#include <vector>
#include <unistd.h>
#include <fstream>

#include "gecko.h"
#include "hacks.h"
#include "settings.h"
#include "error.h"
#include "font.h"
#include "mem2_manager.h"

std::vector<system_hack> system_hacks;
u32 *states_hash=NULL;
unsigned int foff=0;

bool reading_nand = false;
s64 file_offset = 0;
std::ifstream* sd_file_handler = NULL;
s32 nand_file_handler = -1;
s32 file_size = 0;

//TODO : delete this function & everything it uses when we are done
s8 LoadSystemHacks_Old(bool Force_Load_Nand);

void _showError(const char* errorMsg, ...)
{
	char astr[2048];
	memset(astr, 0, 2048);

	va_list ap;
	va_start(ap, errorMsg);

	vsnprintf(astr, 2047, errorMsg, ap);

	va_end(ap);

	PrintString(1, ((640 / 2) - ((strlen(astr)) * 13 / 2)) >> 1, 208, astr);
	sleep(5);
	return;
}

bool GetLine(std::string& line)
{
	char* buf = NULL;	
	try
	{
		//Read untill a newline is found		
		if (reading_nand)
		{
			u32 read_count = 0;
			u32 file_pos = 0;
			const u16 max_loop = 1000;
			const u32 block_size = 32;

			//get current file position
			STACK_ALIGN(fstats, status, sizeof(fstats), 32);
			ISFS_GetFileStats(nand_file_handler, status);
			file_pos = status->file_pos;

			//read untill we have a newline or reach EOF
			gprintf("file_pos : %d \r\nfilesize : %d\r\n",file_pos,status->file_length);
			while (
					file_pos < status->file_length &&
					( 
						buf == NULL || 
						(
							file_pos+strnlen(buf,block_size*max_loop) < status->file_length &&
							strstr(buf, "\n") == NULL && 
							strstr(buf, "\r") == NULL
						)
					)
				)
			{						
				read_count++;
				//are we dealing with a potential overflow?
				if (read_count > max_loop)
				{
					error = ERROR_MALLOC;
					throw "line to long";
				}

				if (buf)
					buf = (char*)mem_realloc(buf, ALIGN32(block_size*read_count));
				else
					buf = (char*)mem_align(32, block_size*read_count);

				if (!buf)
				{
					error = ERROR_MALLOC;
					throw "error allocating buffer";
				}
				
				u32 addr = (u32)buf;
				if (read_count > 1)
					addr += block_size*(read_count - 1);
				else
					memset(buf, 0, block_size*read_count);

				s32 ret = ISFS_Read(nand_file_handler, (void*)addr, block_size);
				if (ret < 0)
				{
					throw "Error reading from NAND";
				}

				if(strlen(buf) > block_size*max_loop)
				{
					throw "buf has overflown its max size during loop";
				}
			}

			//nothing was read
			if(!buf)
			{
				line = "";
				return false;
			}

			std::string read_line(buf);
			mem_free(buf);

			//find the newline and split the string
			std::string cut_string = read_line.substr(0,read_line.find("\n"));
			if(cut_string.length() == 0)
				std::string cut_string = read_line.substr(0,read_line.find("\r"));

			//set the new file position untill after the \r\n, \r or \n
			file_pos += cut_string.length();

			//cut off any carriage returns
			if(cut_string.back() == '\r')
			{
				cut_string = cut_string.substr(0, cut_string.length() - 1);
				file_pos++;
			}
			if(cut_string.front() == '\r')
				cut_string = cut_string.substr(1, cut_string.length() - 1);

			line = cut_string;
			
			//seek file back correctly
			ISFS_Seek(nand_file_handler, file_pos, SEEK_SET);
		}
		else
		{
			//SD is so much easier... xD
			std::string read_line;
			std::getline(*sd_file_handler, read_line);
			if (read_line.back() == '\r')
				read_line.back() = '\0';
			if (read_line.front() == '\r')
				read_line = read_line.substr(0, read_line.length() - 1);

			line = read_line;
		}
		return line.length() > 0;
	}
	catch (char const* ex)
	{
		if (buf)
			mem_free(buf);

		if(ex)
			gprintf("Exception was thrown : %s\r\n",ex);

		line = "";
		return false;
	}
	catch(...)
	{
		if (buf)
			mem_free(buf);
		
		gprintf("General Exception thrown\r\n");

		line = "";
		return false;
	}
}
bool _processLine(std::string line)
{
	gprintf("processing line : %s\r\n", line.c_str());
	return true;
}

s8 LoadSystemHacks(bool load_nand)
{
	reading_nand = load_nand;
	file_offset = 0;
	file_size = 0;

	//system_hacks already loaded
	if (system_hacks.size()) 
	{
		system_hacks.clear();
		if (states_hash)
		{
			mem_free(states_hash);
		}
	}

	//clear any possible open handlers
	if (reading_nand && nand_file_handler >= 0)
	{
		ISFS_Close(nand_file_handler);
		nand_file_handler = -1;
	}
	else if (!reading_nand && sd_file_handler != NULL)
	{
		if(sd_file_handler->is_open())
			sd_file_handler->close();

		delete sd_file_handler;
		sd_file_handler = NULL;
	}

	//read the hacks file size
	if (!reading_nand)
	{
		sd_file_handler = new std::ifstream("fat:/apps/priiloader/hacks_hash.ini");
		if (!sd_file_handler || !sd_file_handler->is_open())
		{
			sd_file_handler = NULL;
			//_showError("file open error");
			gprintf("fopen error : strerror %s\r\n", strerror(errno));
		}
		else
		{
			sd_file_handler->seekg(0, std::ios::end);
			file_size = sd_file_handler->tellg();

			sd_file_handler->seekg(0, std::ios::beg);
		}		
	}

	//no file opened from FAT device, so lets open the nand file
	if (!sd_file_handler)
	{
		gprintf("opening nand\r\n");
		reading_nand = true;
		nand_file_handler = ISFS_Open("/title/00000001/00000002/data/hackshas.ini", 1);
		if (nand_file_handler < 0)
		{
			gprintf("LoadHacks : hacks_hash.ini not on FAT or Nand. ISFS_Open error %d\r\n", nand_file_handler);
			return 0;
		}

		STACK_ALIGN(fstats, status, sizeof(fstats), 32);
		ISFS_GetFileStats(nand_file_handler, status);
		file_size = status->file_length;
	}

	if (file_size == 0)
	{
		if (!load_nand)
			_showError("Error \"hacks_hash.ini\" is 0 byte!");

		if (reading_nand)
		{
			ISFS_Close(nand_file_handler);
			nand_file_handler = -1;
		}			
		else
		{
			sd_file_handler->close();
			delete sd_file_handler;
			sd_file_handler = NULL;
		}

		return 0;
	}

	//Process File
	std::string line;
	while (GetLine(line))
	{
		_processLine(line);
	}


	//cleanup on aisle 4
	if (reading_nand)
	{
		ISFS_Close(nand_file_handler);
		nand_file_handler = -1;
	}
	else
	{
		sd_file_handler->close();
		delete sd_file_handler;
		sd_file_handler = NULL;
	}

	return 1;
}

char *GetLine( char *astr, unsigned int len)
{
	if( foff >= len )
	{
		return NULL;
	}

	unsigned int llen = 0;
	if( strstr(	astr+foff, "\n" ) == NULL )
	{
		if( strstr( astr+foff, "\0" ) == NULL )
		{
			return 0;
		}
		if(strstr( astr+foff, "\0" ) == (astr+foff))
		{
			llen = len - foff;
		}
		else
			llen = strstr( astr+foff, "\0" ) - (astr+foff);
		if( llen == 0 )
		{
			return NULL;
		}
	}
	else
	{
		llen = strstr( astr+foff , "\n" ) - (astr+foff);
		if( llen == 0 )
		{
			return NULL;
		}
	}

	char *lbuf = (char*)mem_malloc( llen );
	if( lbuf == NULL )
	{
		error = ERROR_MALLOC;
		return 0;
	}
	memset(lbuf,0,llen);
	//silly fix for linux newlines...
	if(strstr( astr, "\r\n" ) != NULL )
	{
		//must be a windows newline D:<
		memcpy( lbuf, astr+foff, llen -1);
		lbuf[llen-1] = 0;
	}
	else
	{
		//linux it is
		memcpy( lbuf, astr+foff, llen);
		lbuf[llen] = 0;
	}
	foff+=llen+1;
	return lbuf;
}

s8 LoadSystemHacks_Old( bool Force_Load_Nand )
{	
	if( system_hacks.size() ) //system_hacks already loaded
	{
		system_hacks.clear();
		if(states_hash)
		{
			mem_free(states_hash);
		}
	}
	if(foff != 0)
		foff=0;
	bool mode = true;
	s32 fd=0;
	char *buf=NULL;
	STACK_ALIGN(fstats,status,sizeof(fstats),32);
	unsigned int size=0;
	FILE* in = NULL;
	if(!Force_Load_Nand)
	{
		in = fopen ("fat:/apps/priiloader/hacks_hash.ini","rb");
		if(!in)
			gprintf("fopen error : strerror %s\r\n",strerror(errno));

	}
	if( !in )
	{
		fd = ISFS_Open("/title/00000001/00000002/data/hackshas.ini", 1 );
		if( fd < 0 )
		{
			gprintf("LoadHacks : hacks_hash.ini not on FAT or Nand. ISFS_Open error %d\r\n",fd);
			return 0;
		} 
		mode = false;
	}
	if( mode )	//read file from FAT
	{
		//read whole file in
		fseek( in, 0, SEEK_END );
		size = ftell(in);
		fseek( in, 0, 0);

		if( size == 0 )
		{
			_showError("Error \"hacks_hash.ini\" is 0 byte!");
			return 0;
		}

		buf = (char*)mem_align( 32, ALIGN32(size));
		if( buf == NULL )
		{
			error = ERROR_MALLOC;
			return 0;
		}
		memset( buf, 0, size );
		if(fread( buf, sizeof( char ), size, in ) != size )
		{
			mem_free(buf);
			_showError("Error reading \"hacks_hash.ini\"");
			return 0;
		}
		fclose(in);

	} else {	//read file from NAND

		ISFS_GetFileStats( fd, status);
		size = status->file_length;
		buf = (char*)mem_align( 32, size );
		if( buf == NULL )
		{
			error = ERROR_MALLOC;
			return 0;
		}
		memset( buf, 0, size );
		ISFS_Read( fd, buf, size );
		ISFS_Close( fd );
	}
	buf[size] = 0;

//read stuff into a nice struct
	char *str=buf;
	char *lbuf=NULL;
	unsigned int line = 1;
	patch_struct temp;
	temp.hash.clear();
	temp.patch.clear();
	system_hack new_system_hacks;

	lbuf = GetLine( str, size );
	if( lbuf == NULL )
	{
		_showError("Syntax error : unexpected EOF @ line %d", line);
		mem_free(buf);
		system_hacks.clear();
		return 0;
	}

	while(1)
	{
		if( lbuf == NULL )
			break;

		if( strstr( lbuf, "[" ) == NULL )
		{
			_showError("Syntax error : missing '[' before 'n' @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		char *s = strtok( lbuf+(strstr( lbuf, "[" )-lbuf) + 1, "]");
		if( s == NULL )
		{
			_showError("Syntax error : missing ']' before 'n' @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		new_system_hacks.desc = s;
		mem_free(lbuf);

		line++;
		lbuf = GetLine( str, size );
		if( lbuf == NULL )
		{
			_showError("Syntax error : unexpected EOF @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		if( strncmp( lbuf, "maxversion",10 ) == 0 )
		{
			if( strstr( lbuf, "=" ) ==  NULL )
			{
				_showError("Syntax error : missing '=' before 'n' @ line %d", line);
				system_hacks.clear();
				return 0;
			}
			s = strtok( lbuf+(strstr( lbuf, "=" )-lbuf) + 1, "\n");
			if( s == NULL )
			{
				_showError("Syntax error : missing value before 'n' @ line %d", line);
				system_hacks.clear();
				return 0;
			}
		} else {
			_showError("Syntax error : expected 'version' before 'n' @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		new_system_hacks.max_version = atoi( s );

		if( new_system_hacks.max_version < 0 )
		{
			_showError("Error : maxversion is zero @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		mem_free(lbuf);
		line++;
		lbuf = GetLine( str, size );
		if( lbuf == NULL )
		{
			_showError("Syntax error : unexpected EOF @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		if( strncmp( lbuf, "minversion",10 ) == 0 )
		{
			if( strstr( lbuf, "=" ) ==  NULL )
			{
				_showError("Syntax error : missing '=' before 'n' @ line %d", line);
				system_hacks.clear();
				return 0;
			}
			s = strtok( lbuf+(strstr( lbuf, "=" )-lbuf) + 1, "\n");
			if( s == NULL )
			{
				_showError("Syntax error : missing value before 'n' @ line %d", line);
				system_hacks.clear();
				return 0;
			}
		} else {
			_showError("Syntax error : expected 'minversion' before 'n' @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		new_system_hacks.min_version = atoi( s );

		if( new_system_hacks.min_version < 0 )
		{
			_showError("Error : minversion is zero @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		mem_free(lbuf);
		line++;
		lbuf = GetLine( str, size );
		if( lbuf == NULL )
		{
			_showError("Syntax error : expected EOF @ line %d", line);
			system_hacks.clear();
			return 0;
		}

		if( strncmp( lbuf, "amount",6 ) == 0 )
		{
			if( strstr( lbuf, "=" ) ==  NULL )
			{
				_showError("Syntax error : missing '=' before 'n' @ line %d", line);
				system_hacks.clear();
				return 0;
			}
			s = strtok( lbuf+(strstr( lbuf, "=" )-lbuf) + 1, "\n");
			if( s == NULL )
			{
				_showError("Syntax error : missing value before 'n' @ line %d", line);
				system_hacks.clear();
				return 0;
			}
		} else {
			_showError("Syntax error : expected 'patches' before 'n' @ line %d", line);
			system_hacks.clear();
			return 0;
		}
		new_system_hacks.amount = atoi( s );

		if( new_system_hacks.amount == 0 )
		{
			_showError("Error : patches amount is zero @ line %d", line);
			system_hacks.clear();
			return 0;
		}
		mem_free(lbuf);
		while(1)
		{
			line++;
			lbuf = GetLine( str, size );
			if(temp.hash.size() > 0 && temp.patch.size() > 0)
			{
				new_system_hacks.patches.push_back(temp);
				temp.hash.clear();
				temp.patch.clear();
			} 
			if( lbuf == NULL || new_system_hacks.patches.size() == new_system_hacks.amount )
			{
				if(	new_system_hacks.patches.size() != new_system_hacks.amount)
				{
					if( lbuf == NULL )
					{
						_showError("Syntax error : unexpected EOF @ line %d", line);
						temp.hash.clear();
						temp.patch.clear();
						system_hacks.clear();
						return 0;
					}
				}
				break;
			}
			
			if( memcmp( lbuf, "hash", 4 ) == 0 )
			{
				if ( temp.hash.size() )
				{
					_showError("Syntax error : missing 'patch' before line %d", line);
					system_hacks.clear();
					return 0;
				}
				if( strstr( lbuf, "=" ) ==  NULL )
				{
					_showError("Syntax error : missing '=' before 'n' @ line %d", line);
					system_hacks.clear();
					return 0;
				}
				s = strtok( lbuf+(strstr( lbuf, "=" )-lbuf) + 1, ",\n");
				if( s == NULL )
				{
					_showError("Syntax error : expected value before 'n' @ line %d", line);
					system_hacks.clear();
					return 0;
				}
				
				do{
					unsigned int hash;
					uint8_t size = 0;
					sscanf(s,"%x",&hash);
					if((hash >> 24))
						size = 4;
					else if((hash & 0xFF0000) >> 16)
						size = 3;
					else if((hash & 0xFF00) >> 8)
						size = 2;
					else if(hash & 0xFF)
						size = 1;
					else
						size = 0;
					switch(size)
					{
						case 4: //full u32 like 0x90FFAADD
							temp.hash.push_back(hash >> 24); //first byte of u32 0x90
						case 3:
							temp.hash.push_back((hash & 0xFF0000) >> 16); //second byte of u32 0xFF
						case 2:
							temp.hash.push_back((hash & 0xFF00) >> 8); //3th byte of u32 0xAA
						case 1:
							temp.hash.push_back(hash & 0xFF); // 4th byte of u32 0xDD
						default:
							break;
					}
				
				}while( (s = strtok( NULL,",\n")) != NULL);
				
			} else if ( memcmp( lbuf, "patch", 5 ) == 0 ) 
			{
				if (temp.patch.size() || temp.hash.size() == 0 )
				{
					_showError("Syntax error : missing 'hash' before line %d", line);
					system_hacks.clear();
					return 0;
				}
				if( strstr( lbuf, "=" ) ==  NULL )
				{
					_showError("Syntax error : missing '=' before 'n' @ line %d", line);
					system_hacks.clear();
					return 0;
				}
				s = strtok( lbuf+(strstr( lbuf, "=" )-lbuf) + 1, ",\n");
				if( s == NULL )
				{
					_showError("Syntax error : expected value before 'n' @ line %d", line);
					system_hacks.clear();
					return 0;
				}
				do{
					unsigned int patch;
					uint8_t size = 0;
					sscanf(s,"%x",&patch);
					if((patch >> 24))
						size = 4;
					else if((patch & 0xFF0000) >> 16)
						size = 3;
					else if((patch & 0xFF00) >> 8)
						size = 2;
					else if(patch & 0xFF)
						size = 1;
					else
						size = 0;
					switch(size)
					{
						case 4: // full u32 -> 4 bytes
							temp.patch.push_back(patch >> 24); //first byte of u32 -> 0x90
						case 3: // 24 bit, 3 bytes
							temp.patch.push_back((patch & 0xFF0000) >> 16); //second byte of u32 -> 0xFF
						case 2: // u16, 2 bytes
							temp.patch.push_back((patch & 0xFF00) >> 8); //3th byte of u32 -> 0xAA
						case 1: // u8, 1 byte
							temp.patch.push_back(patch & 0xFF); // 4th byte of u32 -> 0xDD
						default:
							break;
					}

				}while( (s = strtok( NULL,",\n")) != NULL);
			} else {
				if(new_system_hacks.patches.size() > 0 || temp.hash.size() > 0 || temp.patch.size() > 0)
					_showError("Syntax Er: not enough 'hash' or 'patch' before line %d", line);
				else
					_showError("Syntax Err : expected 'hash' or 'patch' before line %d", line);
				system_hacks.clear();
				return 0;
			}
			mem_free(lbuf);
		}
		system_hacks.push_back(new_system_hacks);
		new_system_hacks.patches.clear();
		new_system_hacks.desc.clear();
		new_system_hacks.amount = 0;
		new_system_hacks.max_version = 0;
		new_system_hacks.min_version = 0;
	}
	mem_free(buf);

	if(system_hacks.size()==0)
		return 0;

	//load hack states_hash (on/off)
	if ( states_hash == NULL )
	{
		states_hash = (u32*)mem_align( 32, ALIGN32( sizeof( u32 ) * system_hacks.size() ) );
		if( states_hash == NULL )
		{
			error = ERROR_MALLOC;
			return 0;
		}
	}

	memset( states_hash, 0, sizeof( u32 ) * system_hacks.size() );

	fd = ISFS_Open("/title/00000001/00000002/data/hacksh_s.ini", 1|2 );

	if( fd < 0 )
	{
		//file not found create a new one
		fd = ISFS_CreateFile("/title/00000001/00000002/data/hacksh_s.ini", 0, 3, 3, 3);
		if(fd < 0 )
		{
			return 0;
		}

		fd = ISFS_Open("/title/00000001/00000002/data/hacksh_s.ini", 1|2 );
		if( fd < 0 )
			return 0;

		ISFS_Write( fd, states_hash, sizeof( u32 ) * system_hacks.size() );

		ISFS_Seek( fd, 0, 0 );
	}

	memset( status, 0, sizeof(fstats) );

	if(ISFS_GetFileStats( fd, status)<0)
	{
		return 0;
	}

	u8 *fbuf = (u8 *)mem_align( 32, ALIGN32(status->file_length) );
	if( fbuf == NULL )
	{
		error = ERROR_MALLOC;
		return 0;
	}

	memset( fbuf, 0, status->file_length );

	if(ISFS_Read( fd, fbuf, status->file_length )<0)
	{
		mem_free(fbuf);
		return 0;
	}

	if( sizeof( u32 ) * system_hacks.size() < status->file_length )
		memcpy( states_hash, fbuf, sizeof( u32 ) * system_hacks.size() );
	else
		memcpy( states_hash, fbuf, status->file_length );

	mem_free(fbuf);
	ISFS_Close( fd );

	//Set all system_hacks for system menu > max_version || sysver < min_version to 0
	unsigned int sysver = GetSysMenuVersion();
	for( u32 i=0; i < system_hacks.size(); ++i)
	{
		if( system_hacks[i].max_version < sysver || system_hacks[i].min_version > sysver)
		{
			states_hash[i] = 0;
		}
	}
	return 1;
}
