/*
Copyright (C) 2006,2007 StrmnNrmn

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#pragma once

#ifndef CORE_ROMSETTINGS_H_
#define CORE_ROMSETTINGS_H_

#include "Utility/String.h"

//*****************************************************************************
// Configurable settings for a rom
//*****************************************************************************

enum ESaveType
{
	SAVE_TYPE_UNKNOWN = 0,
	SAVE_TYPE_EEP4K,
	SAVE_TYPE_EEP16K,
	SAVE_TYPE_SRAM,
	SAVE_TYPE_FLASH,
};
const u32 NUM_SAVE_TYPES = SAVE_TYPE_FLASH + 1;

enum EExpansionPakUsage
{
	PAK_STATUS_UNKNOWN = 0,
	PAK_UNUSED,
	PAK_USED,
	PAK_REQUIRED,
};
const u32 NUM_EXPANSIONPAK_USAGE_TYPES = PAK_REQUIRED + 1;


struct RomSettings
{
	CFixedString<128>	GameName;
	CFixedString<128>	Comment;
	CFixedString<128>	Info;
	CFixedString<128>	Preview;

	EExpansionPakUsage	ExpansionPakUsage;
	ESaveType			SaveType;

	bool				PatchesEnabled;
	u32					SpeedSyncEnabled;
    float 				Clock;
	bool				DynarecSupported;
	bool				DynarecLoopOptimisation;
	bool				DynarecDoublesOptimisation;
	bool				DoubleDisplayEnabled;
	bool				CleanSceneEnabled;
	bool				ClearDepthFrameBuffer;
	bool				AudioRateMatch;
	bool				VideoRateMatch;
	bool				FogEnabled;
	bool                MemoryAccessOptimisation;
	bool				CheatsEnabled;

	RomSettings();

	~RomSettings();

	void	Reset();
};

#include "Utility/Singleton.h"

//*****************************************************************************
//
//*****************************************************************************
class	RomID;

//*****************************************************************************
//
//*****************************************************************************
class CRomSettingsDB : public CSingleton< CRomSettingsDB >
{
	public:
		virtual					~CRomSettingsDB() {}

		virtual bool			OpenSettingsFile( const char * filename ) = 0;
		virtual void			Commit() = 0;

		virtual bool			GetSettings( const RomID & id, RomSettings * settings ) const = 0;
		virtual void			SetSettings( const RomID & id, const RomSettings & settings ) = 0;
};

const char * ROM_GetExpansionPakUsageName( EExpansionPakUsage pak_usage );
const char *	ROM_GetSaveTypeName( ESaveType save_type );


#endif // CORE_ROMSETTINGS_H_
