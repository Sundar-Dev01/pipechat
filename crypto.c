#include "pipe_chat.h"
#include <string.h>

void caesar_cipher(char *text, int shift)
{
    size_t i;

    for (i = 0U; text[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)text[i];

        if (ch >= (unsigned char)'a' && ch <= (unsigned char)'z') {
            text[i] = (char)('a' + ((ch - (unsigned char)'a' +
                                    (unsigned int)shift) % 26U));
        } else if (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') {
            text[i] = (char)('A' + ((ch - (unsigned char)'A' +
                                    (unsigned int)shift) % 26U));
        }
    }
}

int contains_keyword(const char *text, const char *keyword)
{
    char copy[ISSUE_LENGTH];
    size_t i;

    (void)snprintf(copy, sizeof(copy), "%s", text);
    for (i = 0U; copy[i] != '\0'; ++i) {
        if (copy[i] >= 'A' && copy[i] <= 'Z') {
            copy[i] = (char)(copy[i] - 'A' + 'a');
        }
    }
    return strstr(copy, keyword) != NULL;
}

int detect_priority(const char *issue)
{
    if (contains_keyword(issue, "urgent") ||
        contains_keyword(issue, "critical") ||
        contains_keyword(issue, "emergency") ||
        contains_keyword(issue, "high")) {
        return PRIORITY_HIGH;
    }
    if (contains_keyword(issue, "medium") ||
        contains_keyword(issue, "moderate")) {
        return PRIORITY_MEDIUM;
    }
    return PRIORITY_LOW;
}
