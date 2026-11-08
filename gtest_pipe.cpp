/*
 * Pipe Chat POC - Google Test suite
 * 52 tests: exactly two TEST cases for each of the 26 C functions.
 *
 * Build C files as C objects. Compile main.c with -Dmain=pipe_chat_application_main.
 * Link those objects with this C++ file and Google Test.
 * Coverage must be measured with gcov/lcov; test count alone cannot guarantee 85-90%.
 */
#include <gtest/gtest.h>
extern "C" {
#include "pipe_chat.h"
}
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <iterator>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" int pipe_chat_application_main(void);

class Fd {
 public:
  explicit Fd(int n=-1): n_(n) {}
  ~Fd(){ if(n_>=0) close(n_); }
  int get() const{return n_;}
  void reset(int n=-1){if(n_>=0)close(n_);n_=n;}
 private:int n_;
};
class Capture {
 public:
  Capture(): saved_(dup(1)), f_(tmpfile()) { if(f_){fflush(stdout);dup2(fileno(f_),1);} }
  ~Capture(){if(saved_>=0){fflush(stdout);dup2(saved_,1);close(saved_);}if(f_)fclose(f_);}
  std::string str(){fflush(stdout);long n=ftell(f_);if(n<0)return{};rewind(f_);std::string s((size_t)n,'\0');if(n)fread(&s[0],1,(size_t)n,f_);return s;}
 private:int saved_;FILE*f_;
};
static std::string file_text(){std::ifstream f(LOG_PATH);return {std::istreambuf_iterator<char>(f),{}};}
static void clear_log(){unlink(LOG_PATH);}
static bool get_event(int fd, EventPacket *e, int ms=2000){
  pollfd p{};p.fd=fd;p.events=POLLIN;
  return poll(&p,1,ms)>0 && read_full(fd,e,sizeof(*e))==1;
}
static int child_roundtrip(bool with_ticket){
  int rq[2],ev[2];if(pipe(rq)||pipe(ev))return -1;
  pid_t pid=fork();if(pid<0)return -2;
  if(pid==0){close(rq[1]);close(ev[0]);child_process(rq[0],ev[1]);_exit(1);}
  close(rq[0]);close(ev[1]);Fd wr(rq[1]),rd(ev[0]);
  EventPacket e{};if(!get_event(rd.get(),&e))return -3;
  if(with_ticket){
    RequestPacket r{};r.type=REQ_CREATE;r.ticket_id=901;r.priority=PRIORITY_HIGH;
    snprintf(r.issue,sizeof(r.issue),"%s","urgent link failure");caesar_cipher(r.issue,3);
    if(write_full_packet(wr.get(),&r,sizeof(r)))return -4;
    bool accepted=false;
    for(int i=0;i<3&&!accepted;i++)if(get_event(rd.get(),&e)){caesar_cipher(e.detail,23);accepted=e.type==EVENT_ACCEPTED;}
    if(!accepted)return -5;
  }
  RequestPacket stop{};stop.type=REQ_SHUTDOWN;write_full_packet(wr.get(),&stop,sizeof(stop));wr.reset();
  bool stopped=false;
  for(int i=0;i<3&&!stopped;i++)if(get_event(rd.get(),&e)){caesar_cipher(e.detail,23);stopped=e.type==EVENT_SERVICE_STOPPED&&strstr(e.detail,"shutting down");}
  int status=0;waitpid(pid,&status,0);return stopped&&WIFEXITED(status)?0:-6;
}
static int run_app(const std::string& input, std::string& output)
{
    FILE *input_file = tmpfile();
    FILE *output_file = tmpfile();

    int oldin = dup(STDIN_FILENO);
    int oldout = dup(STDOUT_FILENO);

    if (input_file == nullptr || output_file == nullptr ||
        oldin < 0 || oldout < 0)
    {
        if (input_file != nullptr) fclose(input_file);
        if (output_file != nullptr) fclose(output_file);
        if (oldin >= 0) close(oldin);
        if (oldout >= 0) close(oldout);
        return -1;
    }

    (void)fwrite(input.data(), 1U, input.size(), input_file);
    rewind(input_file);

    (void)fflush(stdout);
    (void)dup2(fileno(input_file), STDIN_FILENO);
    (void)dup2(fileno(output_file), STDOUT_FILENO);

    mode_t mask = umask(0);
    (void)umask(mask);

    int rc = pipe_chat_application_main();

    (void)fflush(stdout);
    rewind(output_file);

    output.assign(
        std::istreambuf_iterator<char>(
            std::ifstream("/dev/null").rdbuf()),
        std::istreambuf_iterator<char>());

    fseek(output_file, 0, SEEK_END);
    long length = ftell(output_file);
    rewind(output_file);

    if (length > 0)
    {
        output.resize(static_cast<size_t>(length));
        (void)fread(&output[0], 1U, static_cast<size_t>(length),
                    output_file);
    }

    (void)dup2(oldin, STDIN_FILENO);
    (void)dup2(oldout, STDOUT_FILENO);

    close(oldin);
    close(oldout);
    fclose(input_file);
    fclose(output_file);

    (void)umask(mask);

    return rc;
}
/* crypto.c */
TEST(CaesarCipher, ShiftsLettersAndWraps){char s[]="xyz XYZ";caesar_cipher(s,3);EXPECT_STREQ("abc ABC",s);}
TEST(CaesarCipher, PreservesPunctuationAndDigits){char s[]="Ticket-123!";caesar_cipher(s,3);EXPECT_STREQ("Wlfnhw-123!",s);}
TEST(ContainsKeyword, MatchesCaseInsensitively){EXPECT_EQ(1,contains_keyword("URGENT network","urgent"));}
TEST(ContainsKeyword, ReturnsFalseForMissingWord){EXPECT_EQ(0,contains_keyword("printer ready","urgent"));}
TEST(DetectPriority, DetectsHighAndHighWins){EXPECT_EQ(PRIORITY_HIGH,detect_priority("medium critical issue"));}
TEST(DetectPriority, DetectsMediumAndDefaultsLow){EXPECT_EQ(PRIORITY_MEDIUM,detect_priority("moderate issue"));EXPECT_EQ(PRIORITY_LOW,detect_priority("general issue"));}

/* ipc.c */
TEST(ReadFull, ReadsWholeBuffer){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);char x[]="abc",y[4]{};ASSERT_EQ(4,write(w.get(),x,4));EXPECT_EQ(1,read_full(r.get(),y,4));EXPECT_STREQ(x,y);}
TEST(ReadFull, ReturnsZeroOnEarlyEof){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);write(w.get(),"x",1);w.reset();char b[4]{};EXPECT_EQ(0,read_full(r.get(),b,4));}
TEST(WriteFullPacket, WritesPacket){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);char x[]="abc",y[4]{};EXPECT_EQ(0,write_full_packet(w.get(),x,4));EXPECT_EQ(1,read_full(r.get(),y,4));EXPECT_STREQ(x,y);}
TEST(WriteFullPacket, RejectsBadDescriptor){char x='x';EXPECT_EQ(-1,write_full_packet(-1,&x,1));}
TEST(SendRequest, SendsAndCountsCreateRequest){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);RequestPacket q{};q.type=REQ_CREATE;IpcStatistics s{};EXPECT_EQ(0,send_request(w.get(),&q,&s));EXPECT_EQ(1ULL,s.total_requests);EXPECT_EQ(sizeof(q),s.bytes_sent);EXPECT_EQ(1ULL,s.encrypted_messages);}
TEST(SendRequest, DoesNotCountFailedWrite){RequestPacket q{};q.type=REQ_CREATE;IpcStatistics s{};EXPECT_EQ(-1,send_request(-1,&q,&s));EXPECT_EQ(0ULL,s.total_requests);}

/* logger.c */
TEST(FormatTime, HandlesZeroTimestamp){char b[64]{};format_time(0,b,sizeof(b));EXPECT_STREQ("Not yet resolved",b);}
TEST(FormatTime, FormatsRealTimestamp){char b[64]{};format_time(1700000000,b,sizeof(b));EXPECT_NE(std::string::npos,std::string(b).find("2023"));}
TEST(AppendLog, CreatesPrivateLogEntry){clear_log();append_log("test-one");EXPECT_NE(std::string::npos,file_text().find("test-one"));struct stat st{};ASSERT_EQ(0,stat(LOG_PATH,&st));EXPECT_EQ(0600,st.st_mode&0777);clear_log();}
TEST(AppendLog, AppendsRatherThanOverwrites){clear_log();append_log("first");append_log("second");auto s=file_text();EXPECT_NE(std::string::npos,s.find("first"));EXPECT_NE(std::string::npos,s.find("second"));clear_log();}
TEST(LogEvent, WritesServiceEvent){clear_log();EventPacket e{};snprintf(e.detail,sizeof(e.detail),"%s","online");log_event(&e);EXPECT_NE(std::string::npos,file_text().find("SERVICE: online"));clear_log();}
TEST(LogEvent, WritesTicketFields){clear_log();EventPacket e{};e.ticket_id=42;e.priority=PRIORITY_HIGH;e.status=STATUS_RESOLVED;snprintf(e.issue,sizeof(e.issue),"%s","link");snprintf(e.detail,sizeof(e.detail),"%s","fixed");log_event(&e);auto s=file_text();EXPECT_NE(std::string::npos,s.find("TK-0042"));EXPECT_NE(std::string::npos,s.find("HIGH"));clear_log();}

/* queue.c */
TEST(QueueInsert, SortsByPriorityAndKeepsFifo){PriorityQueue q{};RequestPacket a{},b{},c{};a.ticket_id=1;a.priority=1;b.ticket_id=2;b.priority=3;c.ticket_id=3;c.priority=3;queue_insert(&q,&a);queue_insert(&q,&b);queue_insert(&q,&c);ASSERT_NE(nullptr,q.head);EXPECT_EQ(2,q.head->id);EXPECT_EQ(3,q.head->next->id);queue_destroy(&q);}
TEST(QueueInsert, InsertsMediumBetweenHighAndLow){PriorityQueue q{};RequestPacket a{},b{},c{};a.priority=1;b.priority=2;c.priority=3;queue_insert(&q,&a);queue_insert(&q,&b);queue_insert(&q,&c);ASSERT_NE(nullptr,q.head);EXPECT_EQ(3,q.head->priority);EXPECT_EQ(2,q.head->next->priority);queue_destroy(&q);}
TEST(QueuePop, PopsHeadAndDecrementsCount){PriorityQueue q{};RequestPacket a{};a.ticket_id=5;a.priority=3;queue_insert(&q,&a);QueueNode*n=queue_pop(&q);ASSERT_NE(nullptr,n);EXPECT_EQ(5,n->id);EXPECT_EQ(0U,q.count);free(n);}
TEST(QueuePop, EmptyQueueReturnsNull){PriorityQueue q{};EXPECT_EQ(nullptr,queue_pop(&q));}
TEST(QueueDestroy, FreesQueuedNodes){PriorityQueue q{};RequestPacket a{};queue_insert(&q,&a);queue_destroy(&q);EXPECT_EQ(nullptr,q.head);EXPECT_EQ(0U,q.count);}
TEST(QueueDestroy, AcceptsEmptyQueue){PriorityQueue q{};queue_destroy(&q);EXPECT_EQ(nullptr,q.head);}

/* service.c */
TEST(ServiceSeconds, ReturnsConfiguredDurations){EXPECT_EQ(HIGH_SECONDS,service_seconds(PRIORITY_HIGH));EXPECT_EQ(MEDIUM_SECONDS,service_seconds(PRIORITY_MEDIUM));EXPECT_EQ(LOW_SECONDS,service_seconds(PRIORITY_LOW));}
TEST(ServiceSeconds, UnknownPriorityUsesLowDuration){EXPECT_EQ(LOW_SECONDS,service_seconds(-1));}
TEST(SendEvent, SendsEncryptedEventPacket){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);EXPECT_EQ(0,send_event(w.get(),EVENT_ACCEPTED,77,2,1,10,11,0,"issue","accepted"));EventPacket e{};ASSERT_EQ(1,read_full(r.get(),&e,sizeof(e)));caesar_cipher(e.detail,23);EXPECT_STREQ("accepted",e.detail);}
TEST(SendEvent, NullStringsBecomeEmpty){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);EXPECT_EQ(0,send_event(w.get(),EVENT_STATUS,0,0,0,0,0,0,nullptr,nullptr));EventPacket e{};ASSERT_EQ(1,read_full(r.get(),&e,sizeof(e)));EXPECT_STREQ("",e.issue);EXPECT_STREQ("",e.detail);}
TEST(ChildProcess, StartsAndStopsOnShutdown){EXPECT_EQ(0,child_roundtrip(false));}
TEST(ChildProcess, AcceptsRequestThenStops){EXPECT_EQ(0,child_roundtrip(true));}

/* ticket.c */
TEST(PriorityText, MapsHighAndMedium){EXPECT_STREQ("HIGH",priority_text(3));EXPECT_STREQ("MEDIUM",priority_text(2));}
TEST(PriorityText, DefaultsToLow){EXPECT_STREQ("LOW",priority_text(-1));}
TEST(StatusText, MapsOpenAndInProgress){EXPECT_STREQ("OPEN",status_text(1));EXPECT_STREQ("IN PROGRESS",status_text(2));}
TEST(StatusText, UnknownStatusLabel){EXPECT_STREQ("UNKNOWN",status_text(-1));}
TEST(FindTicket, FindsNodeInList){TicketRecord b{};b.id=2;TicketRecord a{};a.id=1;a.next=&b;EXPECT_EQ(&b,find_ticket(&a,2));}
TEST(FindTicket, MissingNodeReturnsNull){TicketRecord a{};a.id=1;EXPECT_EQ(nullptr,find_ticket(&a,9));}
TEST(AddTicketRecord, AddsToEmptyHead){TicketRecord*h=nullptr;auto*n=(TicketRecord*)calloc(1,sizeof(TicketRecord));ASSERT_NE(nullptr,n);n->id=8;add_ticket_record(&h,n);ASSERT_NE(nullptr,h);EXPECT_EQ(8,h->id);free_ticket_records(h);}
TEST(AddTicketRecord, AppendsAtTail){TicketRecord a{};a.id=1;TicketRecord*head=&a;auto*n=(TicketRecord*)calloc(1,sizeof(TicketRecord));ASSERT_NE(nullptr,n);n->id=2;add_ticket_record(&head,n);ASSERT_NE(nullptr,a.next);EXPECT_EQ(2,a.next->id);free_ticket_records(a.next);}
TEST(DisplayTicket, PrintsIdPriorityAndIssue){TicketRecord t{};t.id=123;t.priority=3;t.status=1;strcpy(t.issue,"network");Capture c;display_ticket(&t);auto s=c.str();EXPECT_NE(std::string::npos,s.find("TK-0123"));EXPECT_NE(std::string::npos,s.find("network"));}
TEST(DisplayTicket, PrintsUnresolvedTimeText){TicketRecord t{};t.id=2;Capture c;display_ticket(&t);EXPECT_NE(std::string::npos,c.str().find("Not yet resolved"));}
TEST(DisplayAllTickets, HandlesEmptyList){Capture c;display_all_tickets(nullptr);EXPECT_NE(std::string::npos,c.str().find("No tickets"));}
TEST(DisplayAllTickets, PrintsTicketRows){TicketRecord t{};t.id=1;strcpy(t.issue,"printer");Capture c;display_all_tickets(&t);EXPECT_NE(std::string::npos,c.str().find("printer"));}
TEST(DisplayStatistics, PrintsEmptyDashboard){IpcStatistics s{};Capture c;display_statistics(nullptr,&s);EXPECT_NE(std::string::npos,c.str().find("SESSION DASHBOARD"));}
TEST(DisplayStatistics, PrintsCounters){TicketRecord t{};t.priority=3;t.status=1;IpcStatistics s{};s.total_requests=4;Capture c;display_statistics(&t,&s);auto o=c.str();EXPECT_NE(std::string::npos,o.find("High-priority"));EXPECT_NE(std::string::npos,o.find("Requests sent"));}
TEST(FreeTicketRecords, FreesTwoNodes){auto*a=(TicketRecord*)calloc(1,sizeof(TicketRecord));auto*b=(TicketRecord*)calloc(1,sizeof(TicketRecord));ASSERT_NE(nullptr,a);ASSERT_NE(nullptr,b);a->next=b;free_ticket_records(a);SUCCEED();}
TEST(FreeTicketRecords, AcceptsNull){EXPECT_NO_THROW(free_ticket_records(nullptr));}

/* events.c */
TEST(ProcessChildEvents, DecryptsAndUpdatesTicket){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);TicketRecord t{};t.id=55;IpcStatistics s{};ASSERT_EQ(0,send_event(w.get(),EVENT_ACCEPTED,55,3,1,10,20,0,"urgent link","accepted"));EXPECT_EQ(1,process_child_events(r.get(),&t,&s));EXPECT_EQ(3,t.priority);EXPECT_EQ(1,t.status);EXPECT_STREQ("urgent link",t.issue);EXPECT_EQ(1ULL,s.responses_received);}
TEST(ProcessChildEvents, ReturnsZeroWithoutPendingData){int p[2];ASSERT_EQ(0,pipe(p));Fd r(p[0]),w(p[1]);IpcStatistics s{};EXPECT_EQ(0,process_child_events(r.get(),nullptr,&s));}
TEST(ShowHelp, PrintsCommands){Capture c;show_help();auto s=c.str();EXPECT_NE(std::string::npos,s.find("/ticket"));EXPECT_NE(std::string::npos,s.find("/status"));}
TEST(ShowHelp, PrintsPriorityGuide){Capture c;show_help();auto s=c.str();EXPECT_NE(std::string::npos,s.find("PRIORITY KEYWORDS"));EXPECT_NE(std::string::npos,s.find("urgent"));}

/* main.c (compiled with main renamed for this test executable) */
TEST(PipeChatMain, StartsAndQuits){std::string out;EXPECT_EQ(EXIT_SUCCESS,run_app("/quit\n",out));EXPECT_NE(std::string::npos,out.find("PIPE CHAT - CUSTOMER SUPPORT SYSTEM"));EXPECT_NE(std::string::npos,out.find("session closed"));}
TEST(PipeChatMain, CreatesTicketAndQuits){std::string out;EXPECT_EQ(EXIT_SUCCESS,run_app("/ticket urgent gtest network issue\n/quit\n",out));EXPECT_NE(std::string::npos,out.find("TK-1001"));EXPECT_NE(std::string::npos,out.find("gtest network issue"));}


