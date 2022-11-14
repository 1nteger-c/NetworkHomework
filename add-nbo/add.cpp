#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include <netinet/in.h>
void  add(char * name1, char * name2){
	FILE *fp1 = fopen(name1,"r");
	FILE *fp2 = fopen(name2,"r");
	if( fp1 == NULL || fp2 == NULL){
	printf("File error\n");
	return ;
}
	uint32_t * one;
	uint32_t * two;
	uint32_t res,res1,res2;
	one = (uint32_t *)malloc(2);
	two = (uint32_t *)malloc(2);
	fread(one,1,4,fp1);
	fread(two,1,4,fp2);
	res1 = ntohl(*one);
	res2 = ntohl(*two);
	res = res1 + res2;
	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n",res1,res1,res2,res2,res,res);
}
