all:
	gcc -std=c11 -Wall -Wextra -o pipe_chat main.c crypto.c events.c ipc.c logger.c  queue.c service.c ticket.c

run:
	./pipe_chat

valgrind:
	valgrind --trace-children=yes --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ./pipe_chat

gtest:
	gcc -std=c11 --coverage -Dmain=pipe_chat_application_main -c main.c -o main.o
	gcc -std=c11 --coverage -DENABLE_GCOV_DUMP -c crypto.c events.c ipc.c logger.c queue.c service.c ticket.c
	g++ -std=c++17 --coverage -o gtest_runner "gtest_pipe.cpp" main.o crypto.o events.o ipc.o logger.o queue.o service.o ticket.o -lgtest -lgtest_main -pthread
	./gtest_runner

coverage:
	gcov -b -c main.c crypto.c events.c ipc.c logger.c  queue.c service.c ticket.c

cppcheck:
	cppcheck --enable=all --inconclusive --std=c11 --language=c --suppress=missingIncludeSystem *.c 2> cppcheck.txt

misra:
	cppcheck --platform=unix64 --addon=misra --std=c11 --language=c --suppress=missingIncludeSystem *.c 2> misra.txt

clean:
	rm -f pipe_chat gtest_runner *.o *.gcda *.gcno *.gcov cppcheck.txt misra.txt
