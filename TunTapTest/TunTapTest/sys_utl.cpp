#include "sys_utl.h"
#include "net_utl.h"

ThreadBase::ThreadBase()
{
	_fStop = false;
	_fStopped = false;
}

ThreadBase::~ThreadBase()
{
	return;
}

int ThreadBase::start()
{
	_fStop = false;
#ifdef WIN32
	unsigned uTid;
	if(_beginthreadex(NULL, 0, ThreadBase::doTask, this, 0, &uTid) == NULL)
		return -1;
#else
	pthread_t tid;
	int ret = pthread_create(&tid, NULL, ThreadBase::doTask, this);
	if(ret != 0) {
		return -1;
	}
	pthread_detach(tid);
#endif
	return 0;
}

#ifdef WIN32
uint32 __stdcall
#else
void* 
#endif
ThreadBase::doTask(void* pData)
{
	ThreadBase* pThis = (ThreadBase*)pData;
//	printf("Begin ThreadBase::ThreadFunc() self:%u\n", (uint32)pthread_self());
	pThis->ThreadFunc();
	pThis->_fStopped = true;
//	printf("End  ThreadBase::ThreadFunc() self:%u\n", (uint32)pthread_self());
	return NULL;
}

