/************************************************************************/
/*   Author: Jackwu@tvuentworks.com                                     */
/*   Date: 2013-4-22                                                   */
/************************************************************************/
#ifndef ___SYS_UTL_H__
#define ___SYS_UTL_H__
#include "net_utl.h"
#include <list>
#include <string>

#ifdef WIN32
	#define PI64 "%I64"
#else
	#define PI64 "%ll"
#endif

#ifndef max
	#define sys_max(a, b)   ((a) > (b) ? (a) : (b))
	#define sys_min(a, b)   ((a) < (b) ? (a) : (b))
#endif

#ifdef WIN32
	#include <windows.h>
	#include <winioctl.h>
	#include <process.h>
	#define MUTEX_T CRITICAL_SECTION
	#define MUTEX_INIT(l) InitializeCriticalSection(l)
	#define MUTEX_LOCK(l) EnterCriticalSection(l)
	#define MUTEX_UNLOCK(l) LeaveCriticalSection(l)
	#define MUTEX_DESTROY(l) DeleteCriticalSection(l)
#else
	#include <pthread.h>
	#define MUTEX_T pthread_mutex_t
	#define MUTEX_INIT(l) pthread_mutex_init(l, NULL)
	#define MUTEX_LOCK(l) pthread_mutex_lock(l)
	#define MUTEX_UNLOCK(l) pthread_mutex_unlock(l)
	#define MUTEX_DESTROY(l) pthread_mutex_destroy(l)
	#include <dirent.h>
#endif

struct ThreadMsgBase
{
	uint16 uCmd;
	uint16 uFlag;
	uint32 uLen;
};

#define QUEUE_SIZE 200

class MsgQueue
{
public:
	MUTEX_T _lock;
	std::list<ThreadMsgBase* > _listMsgs;
	int _nSize;
public:
	MsgQueue() {
		MUTEX_INIT(&_lock);
		_listMsgs.clear();
		_nSize = 0;
	}
	~MsgQueue() {
		MUTEX_DESTROY(&_lock);
	}

	void putMsg(ThreadMsgBase *pMsg) {
		MUTEX_LOCK(&_lock);
		_listMsgs.push_back(pMsg);
		_nSize = _listMsgs.size();
		MUTEX_UNLOCK(&_lock);
	}
	ThreadMsgBase* getMsg() {
		ThreadMsgBase* pMsg = NULL;
        if (_nSize == 0) {
            return NULL;
        }
		MUTEX_LOCK(&_lock);
		if (_listMsgs.empty() == false) {
			pMsg = _listMsgs.front();
			_listMsgs.pop_front();
		}
		_nSize = _listMsgs.size();
		MUTEX_UNLOCK(&_lock);
		return pMsg;
	}

	void clear() {
		MUTEX_LOCK(&_lock);
		while(!_listMsgs.empty()) {
			ThreadMsgBase *pMsg = _listMsgs.front();
			_listMsgs.pop_front();
			free(pMsg);
		}
		_nSize = _listMsgs.size();
		MUTEX_UNLOCK(&_lock);
		return;
	}
	int size() {
		return _nSize;
	}
};

class ThreadBase
{
public:
	ThreadBase();
	virtual ~ThreadBase();
public: // thread 
	MsgQueue _oMsgQueue;
	bool _fStop;
	bool _fStopped;
public:
	void stop() { _fStop = true;}
	bool isStopped() { return _fStopped; }
	virtual int ThreadFunc() { return 0; }
#ifdef WIN32
	static uint32 __stdcall doTask(void* pData);
#else
	static void* doTask(void* pData);
#endif
	int start();
};

#endif /* ___SYS_UTL_H__ */

