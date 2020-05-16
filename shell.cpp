#include <stdio.h>
#include <unistd.h>
#include <cstdlib>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <cstring>
#include <string>
#include <vector>

using namespace std;

int basepid = 0;

void run(int signum){}

void child(int signum)
{
	int status = 0;
	wait(&status);
	signal(SIGCHLD,child);
}

void gen_args(string comm,char* args[64])
{
	int argnum = 0;
	int pos = 0;
	unsigned int size = comm.size();
	char* buf = (char*)malloc(16*sizeof(char));
	for (int i = 0; i < size; i++)
	{
		buf[pos++] = comm[i];
		if ((comm[i]==' ') || (i+1==size))
		{
			buf[pos-(i+1==size?0:1)] = '\0';
			args[argnum++] = buf;
			if ((i+1)==size)
			{
				args[argnum] = nullptr;
				break;
			}
			pos = 0;
			while (comm[i+1] == ' ') i++;
			buf = (char*)malloc(16*sizeof(char));
		}
	}
}

void parse_bash(vector<string>& bash, char* comm)
{
	while (*comm!='\0')
	{
		char buf[64];
		int i = 0;
		while (*comm==' ') comm++;
		while ((*comm != '\0') && (*comm!='|'))
		{
			buf[i++] = *(comm++);
		}
		while (buf[i-1]==' ') 
		{
			i--;
		}
		buf[i] = '\0';
		bash.push_back(string(buf)); 
		if (*comm == '|') comm++;
	}
}

void cont_exec(vector<string> bash, int index_1, int index_2)
{
	signal(SIGCHLD,child);
	int fd[2];
	pipe(fd);
	if (fork()==0)
	{
		dup2(fd[0],0);
		close(fd[1]);
		// if bash[index_2] is not the last command
		if (index_2 != (bash.size()-1))
		{
			cont_exec(bash,index_1+1,index_2+1);
		}
		else
		{
			close(1);
			int file = open("result.out",O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
			dup2(file,1);
			char* args[64];
			gen_args(bash[index_2],args);
			kill(basepid,SIGCONT);
			execvp(args[0],args);
		}
	}
	else
	{
		if (getpid() == basepid)
		{
			//expect a process tree to be built
			signal(SIGCONT,run);
			pause();
		}
		char* args[64];
		gen_args(bash[index_1],args);
		dup2(fd[1],1);
		close(fd[0]);
		execvp(args[0],args);
	}
}
int main(int argc, char **argv)
{	
	basepid = getpid();
	
	//parse input
	vector<string> bash;
	char c;
	int index = 0;
	char comm[1024];
	while(((c=getchar())!='\n')&&c!=EOF)
	{
		comm[index++] = c;
	}
	comm[index] = '\0';
	parse_bash(bash, (char*)comm);
	if (bash.size()>1)
		cont_exec(bash,0,1);
	else
	{
		close(1);
		int file = open("result.out",O_RDWR | O_CREAT | O_TRUNC);
		dup2(file,1);
		char* args[64];
		gen_args(bash[0],args);
		execvp(args[0],args);
	}
    return 0;
}
