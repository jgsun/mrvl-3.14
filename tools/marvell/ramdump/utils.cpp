/*------------------------------------------------------------
(C) Copyright [2006-2008] Marvell International Ltd.
All Rights Reserved
------------------------------------------------------------*/

#include "rdp.h"

char* changeExt(const char* inName,const char* ext)
{
	char* outName=(char*)malloc(strlen(inName)+strlen(ext)+1+1); //+ext+'.'+\0
	int i,exti;
	if(outName)
	{
	  for(i=0, exti=-1;inName[i];i++)
	  {
		  if((outName[i]=inName[i])=='.') exti=i;
	  }

	  if(exti<0) //no dot
	  {
		  exti=i;
		  outName[exti]='.';
	  }
	  strcpy(&outName[exti+1],ext);
	}
    return outName;
}

// Inherit the path
char* changeNameExt(const char* inName,const char* nameext)
{
	int len;
	const char *p;
	const char *pp=0;

	// Find path last '\'
	for(p=inName; p=strchr(p,PATH_SLASH); pp=++p);
	len = pp?pp-inName:0;

	char* outName=(char*)malloc(strlen(nameext)+len+1); // +\0

	if(outName)
	{
		strncpy(outName, inName, len);
		outName[len]=0;
		strcat(outName, nameext);
	}
    return outName;
}

const char* getExt(const char* inName)
{
	int i,exti;
	  for(i=0, exti=-1;inName[i];i++)
	  {
		  if(inName[i]=='.') exti=i;
	  }

	  if(exti<0) //no dot
	  {
		  exti=i;
	  }
	  else
	  {
		  exti++;
	  }
    return &inName[exti];
}
