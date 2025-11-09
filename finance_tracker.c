// finance_tracker.c

/*
    Authors: Urvashi Panwala,Isha Sheth, Bibek Bhatt
    CS455 - Secure Software Development Final Project
    Verification version

*/

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <stdint.h>

#include <ctype.h>

#include <openssl/sha.h>

#include <unistd.h>

#include <errno.h>

#include <fcntl.h>

#include <sys/file.h>

#include <stdbool.h>

#include <termios.h>

// Vulnerability Instance ID 10-1 (Not Updating Easily) nothing critical or major but filenames like "users.dat" and "record.bin" were used directly in multiple functions,
// making it difficult to update filenames across the codebase.
// Resolution: All filenames are now centralized in `#define` macros at the top of the file

#define MAX_USERNAME_LEN 32

#define MAX_PASSWORD_LEN 32

#define MAX_LINE_LEN 256

#define MAX_CATEGORY_LEN 50

#define MAX_DATE_LEN 30

#define MAX_AMOUNT 100000000000000.00

#define CONFIG_SALT "Fin@123$"

#define CONFIG_USER_FILE "users.dat"

#define CONFIG_RECORD_FILE "record.bin"

#define CONFIG_INCOME_FILE "myincome.bin"

#define CONFIG_EXPENSE_FILE "myexpense.bin"

struct Node
{

    char date[MAX_DATE_LEN];

    double amount;

    char category[MAX_CATEGORY_LEN];

    struct Node *next;
};

struct Record
{

    double income;

    double expense;
};

struct Node *incomeList = NULL, *expenseList = NULL;

double currentIncome = 0, currentExpense = 0;

// Primary author: Bibek Bhatt
// Function declarations
// Description: Clears the stdin buffer

void clearStdin();

char *secureInput(char *buffer, size_t size);

void hashPassword(const char *password, char *hashed, const char *salt);

void registerUser();

int loginUser();

void showMainMenu();

void showFinanceMenu();

void addIncome();

void addExpense();

void displayRecords(struct Node *list, const char *type);

void saveIncome();

void saveExpense();

void loadIncome();

void loadExpense();

void saveRecord();

void loadRecord();

void freeList(struct Node *list);

int fileExists(const char *filename);

// this functions validates date user enters making sure its entered within its restrictions
bool validateDate(const char *date)
{
    if (strlen(date) != 10)
        return false;
    if (date[2] != '-' || date[5] != '-')
        return false;
    for (int i = 0; i < 10; i++)
    {
        if (i == 2 || i == 5)
            continue;
        if (!isdigit((unsigned char)date[i]))
            return false;
    }
    int month = (date[0] - '0') * 10 + (date[1] - '0');
    int day = (date[3] - '0') * 10 + (date[4] - '0');
    int year = atoi(date + 6);
    if (month < 1 || month > 12)
        return false;
    if (day < 1 || day > 31)
        return false;
    if (year < 1900)
        return false;
    return true;
}

//Author: Bibek Bhatt
// this functions validates username and passwords with regard to their restrictions
// Returns true if username or password is 3–16 chars, starts with a letter,
// and contains only letters, digits, '_', '@', '-', or '.'
bool validateUsernamePassword(const char *u)
{
    size_t len = strlen(u);

    if (len < 3 || len > 16)

        return false; // enforce length 

    if (!isalpha((unsigned char)u[0]))

        return false; // must start with A–Z or a–z

    for (size_t i = 1; i < len; i++)
    {
        char c = u[i];

        if (!(isalnum((unsigned char)c) || c == '_' || c == '@' || c == '-' || c == '.'))
        {

            return false; // reject anything not in our expanded set

        }

    }

    return true;
}

// Primary author: Bibek Bhatt
// Description: Hashes a password using SHA256 with a salt
// Inputs: Password to be hashed, buffer for the hashed password, salt value

// Vulnerability Instance ID 12-1 (Failure to Protect Stored Data) a weak custom hash function (djb2-style) was used, which made it trivial to reverse or brute-force stored passwords.
// Resolution: Passwords are now hashed with SHA-256 and salted using a defined constant. This ensures passwords are stored securely and resist dictionary attacks.

void hashPassword(const char *password, char *hashed, const char *salt)
{

    char saltedPass[MAX_PASSWORD_LEN + 64];

    snprintf(saltedPass, sizeof(saltedPass), "%s%s", salt, password);

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char *)saltedPass, strlen(saltedPass), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {

        sprintf(&hashed[i * 2], "%02x", hash[i]);
    }

    hashed[64] = '\0';
}

// Primary author: Bibek Bhatt
// Description: Safely accepts user input and removes newline character
// Inputs: Buffer to store input, size of buffer
// Outputs: Inputted string
// Vulnerability Instance ID 1-1 (Buffer Overflow) — Prevents buffer overflow compared to unsafe gets()
// Resolution: Uses fgets with size limit and newline sanitization to ensure input safety

// Vulnerability Instance ID 4-1 (Catching Exceptions) the return value of `fgets()` was not checked/ unchecked return valur was ignored
// If input failed, the code continued with uninitialized input, leading to undefined behavior.
// Resolution: Now checks `fgets()` return value. If it fails, it clears stdin, shows an error,
// and asks the user to try again safely.

char *secureInput(char *buffer, size_t size)
{

    while (1)
    {

        if (fgets(buffer, size, stdin))
        {

            buffer[strcspn(buffer, "\n")] = '\0';

            return buffer;
        }
        else
        {

            clearStdin();

            fprintf(stderr, "[ERROR] Invalid input. Try again.\n");
        }
    }
}

//Primary author: Bibek Bhatt
// Description: Reads password into buffer (size-1), masks with '*' on screen, important for user privacy
// Vulnerability Instance ID 7-2 (Information leakage) password characters were visible as typed, exposing them to shoulder-surfing.  
//   Resolution: getPassword() disables terminal echo (ECHO|ICANON off) so input is masked with ‘*’

void getPassword(char *buffer, size_t size)
{
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt); // save current terminal state
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON); // disable echo & canonical mode
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    size_t idx = 0;
    int c;
    while (idx < size - 1)
    {
        c = getchar();
        if (c == '\n' || c == EOF)
            break; // Enter or EOF ends input
        if (c == 127 || c == '\b')
        { // handle Backspace
            if (idx > 0)
            {
                idx--;
                // move cursor back, overwrite with space, move back again
                printf("\b \b");
            }
        }
        else
        {
            buffer[idx++] = (char)c;
            putchar('*'); // print mask
        }
    }
    buffer[idx] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restore terminal
    printf("\n");                            // newline after Enter
}

// Clears the standard input buffer to handle leftover characters (e.g., from invalid scanf)

void clearStdin()
{

    int c;

    while ((c = getchar()) != '\n' && c != EOF)
    {
    }
}

// Checks if a file exists
// Input: filename (string)
// Output: 1 if file exists, 0 otherwise

int fileExists(const char *filename)
{

    return access(filename, F_OK) != -1;
}

// Primary author: Urvashi Panwala
// Description: Handles user registration by storing username and hashed password with necessary requirements
// Vulnerability Instance ID 1-3(Buffer overflow) - gets(username) was used which had no bound check
// resolution: use of secureInput() to get username which uses fgets in it

// Vulnerability instance ID 2-1 (format string problem) - fprintf(file, username);` was used,
//  which allowed attackers to inject format specifiers (e.g., %x, %n), causing data leakage or corruption.
//  Resolution - Replaced with `fprintf(file, "%s:%s\n", username, hashed);` to safely write user data

// Vulnerability Instance ID 6-4 (Failure to Handle Errors Correctly) fopen() failures were only perror()’d and execution continued, risking writes to a NULL FILE*.
// Resolution: Immediately return if fopen() fails.

// Vulnerability Instance ID 8-1 (Race Condition) writing to `users.dat` occurred without a lock, allowing simultaneous registrations to corrupt the file.
//  Resolution: An exclusive file lock (`flock(fd, LOCK_EX)`) was added before writing,and released with `flock(fd, LOCK_UN)` after the operation.

// Vulnerability Instance ID 9-2 (Poor Usability) after successful registration, no guidance was provided.
// Resolution: After successful registration, prints a clear confirmation message  “[INFO] User registered successfully.”).

void registerUser()
{

    char username[MAX_USERNAME_LEN], password[MAX_PASSWORD_LEN], hashed[65];

    char salt[] = CONFIG_SALT;

    do
    {
        printf("Enter a username (3–16 chars, start with a letter, letters/digits/'_', '@', '-', or '.'): ");
        secureInput(username, sizeof(username));
        if (!validateUsernamePassword(username))
        {
            fprintf(stderr, "[ERROR] Invalid username. Must be 3–16 chars, start with a letter, and contain only letters, digits, '_', '@', '-', or '.'\n");
        }
    } while (!validateUsernamePassword(username));

    do
    {
        printf("Enter a password (3–16 chars, letter-first, letters/digits/_@.-; not same as username): ");
        getPassword(password, sizeof(password));
        if (!validateUsernamePassword(password))
        {
            fprintf(stderr,
                    "[ERROR] Invalid password. Must follow the same 3–16-char rules as username.\n");
        }
        else if (strcmp(password, username) == 0)
        {
            fprintf(stderr, "[ERROR] Password cannot be the same as your username.\n");
        }
    } while (!validateUsernamePassword(password) || strcmp(password, username) == 0);

    hashPassword(password, hashed, salt);

    FILE *file = fopen(CONFIG_USER_FILE, "a");

    if (!file)
    {
        perror("[ERROR] Failed to open file");
        return;
    }

    int fd = fileno(file);

    flock(fd, LOCK_EX);

    fprintf(file, "%s:%s\n", username, hashed);

    flock(fd, LOCK_UN);

    fclose(file);

    printf("[INFO] User registered successfully.\n");
}

// Primary author: Urvashi Panwala
// Description: Verifies login by comparing username and hashed password from input with warning if prompted wrong credentials
// Vulnerability Instance ID 2-2 (Format String Problem)`printf(password);` was used to print the user input
// allowing an attacker to input format specifiers and read sensitive memory.
// Resolution: all user input is printed using fixed format strings or omitted entirely. This avoids exposing format string vulnerabilities.

// Vulnerability Instance ID 6-5 (Failure to Handle Errors Correctly) fopen() failures printed a generic info message, then continued as if the file existed.
// Resolution: Prints a clear error to stderr and gets out of the login function.

// Vulnerability Instance ID 7-1 not really but close(Information Leakage) —   “No user data found” vs “wrong password,” allowing attackers to discover valid usernames.
// Resolution: Missing file and bad-password cases both produce generic “Login failed,” but when no data file exists it first prints “[INFO] No user data found. Please register first.” to avoid revealing valid usernames

// Vulnerability Instance ID 9-1 (Poor Usability) failed login printed “Login failed” with no direction.
// Resolution: Now includes a user-friendly suggestion that says no user found and register.
int loginUser()
{

    char username[MAX_USERNAME_LEN], password[MAX_PASSWORD_LEN], hashed[65];

    char line[MAX_LINE_LEN], salt[] = CONFIG_SALT;

    printf("Enter username: ");

    secureInput(username, sizeof(username));

    printf("Enter password: ");

    getPassword(password, sizeof(password));

    hashPassword(password, hashed, salt);

    FILE *file = fopen(CONFIG_USER_FILE, "r");

    if (!file)
    {

        printf("[INFO] No user data found. Please register first.\n");

        return 0;
    }

    int authenticated = 0;

    while (fgets(line, sizeof(line), file))
    {

        char storedUser[MAX_USERNAME_LEN], storedHash[65];

        if (sscanf(line, "%31[^:]:%64s", storedUser, storedHash) == 2)
        {

            if (strcmp(username, storedUser) == 0 && strcmp(hashed, storedHash) == 0)
            {

                authenticated = 1;

                break;
            }
        }
    }

    fclose(file);

    if (authenticated)
    {

        printf("[INFO] Login successful.\n");

        return 1;
    }
    else
    {

        printf("[INFO] Login failed.\n");

        return 0;
    }
}
// Primary author: Isha Sheth
// Description: Adds a new entry (income or expense) to the corresponding linked list. warnings given if inputs are out of required ones
// Parameters:
// - list: Pointer to linked list where the entry is added
// - total: Pointer to the cumulative total to update
// - type: Type of entry ("Income" or "Expense") for user prompts
// Vulnerability Instance ID 1-2 (Buffer Overflow) — Previously used strcpy() which overflows on long date/category
// Resolution: strncpy() is used instead to limit copied characters and avoid overflow.

// Vulnerability Instance ID 3-1 (Integer Overflow) `scanf("%u", &amount);` was used with no limit,
// allowing very large values to cause overflow or logical errors.
// Resolution: The input is now stored as a `double`, and checked to be within 0 and MAX_AMOUNT.
// This prevents any overflow, underflow, or invalid values from corrupting calculations.

// Vulnerability Instance ID 4-2 (Catching Exceptions) `scanf()` return value was unchecked, if user enters a letter it fails but execution continues
// could cause leftover input to corrupt further logic.
// Resolution: Replaced scanf() with secureInput()+strtod(); explicitly validates parse results, range, and flushes stdin on invalid input.

// Vulnerability Instance ID 6-3 (Failure to Handle Errors Correctly) memory-allocation failures were ignored, which could lead to null-pointer dereferences.
// Resolution: Check calloc() return and abort on failure.

void addEntry(struct Node **list, double *total, const char *type)
{

    struct Node *newNode = calloc(1, sizeof(struct Node));

    if (!newNode)
    {
        fprintf(stderr, "[ERROR] Memory allocation failed.\n");
        return;
    }

    char date[MAX_DATE_LEN], category[MAX_CATEGORY_LEN];

    double amount;

    do
    {
        printf("Enter date (MM-DD-YYYY): ");
        secureInput(date, sizeof(date));
        if (!validateDate(date))
        {
            fprintf(stderr,
                    "[ERROR] Invalid date. Use MM-DD-YYYY (e.g. 04-01-2025).\n");
        }
    } while (!validateDate(date));

    char amtBuf[64];
    char *endptr;
    errno = 0;
    do
    {
        printf("Enter amount (>= 0): ");
        secureInput(amtBuf, sizeof(amtBuf));

        // parse it
        amount = strtod(amtBuf, &endptr);

        // validate
        if (endptr == amtBuf   // nothing parsed
            || *endptr != '\0' // trailing junk
            || amount < 0.0    // negative
            || errno == ERANGE)
        { // out-of-range
            fprintf(stderr, "[ERROR] Invalid amount. Please enter a non-negative number.\n");
            errno = 0;     // reset for next strtod
            amount = -1.0; // force loop
        }
    } while (amount < 0.0);

    printf("Enter category: ");

    secureInput(category, sizeof(category));

    strncpy(newNode->date, date, MAX_DATE_LEN - 1);
    newNode->date[MAX_DATE_LEN - 1] = '\0';

    strncpy(newNode->category, category, MAX_CATEGORY_LEN - 1);
    newNode->category[MAX_CATEGORY_LEN - 1] = '\0';

    newNode->amount = amount;

    newNode->next = NULL;

    if (!(*list))
        *list = newNode;

    else
    {

        struct Node *ptr = *list;

        while (ptr->next)
            ptr = ptr->next;

        ptr->next = newNode;
    }

    *total += amount;

    printf("[INFO] %s entry added successfully.\n", type);
}

void addIncome()
{
    addEntry(&incomeList, &currentIncome, "Income");
    saveIncome();
}

void addExpense()
{
    addEntry(&expenseList, &currentExpense, "Expense");
    saveExpense();
}

// Primary author: Isha Sheth
// Description: Prints each record’s date, amount, and category from the linked list
// Vulnerability Instance ID 2-3 (Format String Problem)
// In the vulnerable version, `printf(ptr->category);` printed user input directly,
// exposing the program to format string attacks (e.g., entering %x %x as category).
// Resolution: Now uses a controlled format string:
// `printf("Date: %s | Amount: %.2lf | Category: %s\n", ...)` which treats input as plain data.
void displayRecords(struct Node *list, const char *type)
{

    if (!list)
    {

        printf("[INFO] No %s records to display.\n", type);

        return;
    }

    struct Node *ptr = list;

    printf("\n--- %s Records ---\n", type);

    while (ptr)
    {

        printf("Date: %s | Amount: %.2lf | Category: %s\n", ptr->date, ptr->amount, ptr->category);

        ptr = ptr->next;
    }
}

// Primary author: Isha Sheth
// Description: Saves a linked list to a binary file
// Inputs: linked list pointer, filename

void saveToFile(struct Node *list, const char *filename)
{

    FILE *fp = fopen(filename, "wb");

    if (!fp)
    {
        perror("[ERROR] Cannot save to file");
        return;
    }

    struct Node *ptr = list;

    while (ptr)
    {

        fwrite(ptr, sizeof(struct Node), 1, fp);

        ptr = ptr->next;
    }

    fclose(fp);
}

// Primary author: Bibek Bhatt
// Description: Loads a linked list from a binary file
// Inputs: pointer to linked list, filename
// Vulnerability Instance ID 6-2 (Failure to Handle Errors Correctly) —  ignored fopen failures and fread errors, making it impossible to know if data was loaded.
// Resolution: Prints an informational message if the data file is not found, checks the result of each fread call, reports any read errors  and only populates the list when valid data is read

void loadFromFile(struct Node **list, const char *filename)
{

    FILE *fp = fopen(filename, "rb");

    if (!fp)
    {
        fprintf(stderr, "[INFO] No data file found: %s\n", filename);
        return;
    }

    struct Node *head = NULL, *tail = NULL;

    struct Node temp;

    while (fread(&temp, sizeof(struct Node), 1, fp))
    {

        struct Node *node = calloc(1, sizeof(struct Node));

        if (!node)
        {
            fprintf(stderr, "[ERROR] Memory error.\n");
            break;
        }

        *node = temp;

        node->next = NULL;

        if (!head)
            head = tail = node;

        else
        {
            tail->next = node;
            tail = node;
        }
    }

    fclose(fp);

    *list = head;
}

void saveIncome() { saveToFile(incomeList, CONFIG_INCOME_FILE); }

void saveExpense() { saveToFile(expenseList, CONFIG_EXPENSE_FILE); }

void loadIncome() { loadFromFile(&incomeList, CONFIG_INCOME_FILE); }

void loadExpense() { loadFromFile(&expenseList, CONFIG_EXPENSE_FILE); }

// Primary author: Urvashi Panwala
// Description: Saves current income and expense totals to file
// Loads income and expense totals from file

void saveRecord()
{

    FILE *fp = fopen(CONFIG_RECORD_FILE, "wb");

    if (!fp)
    {
        perror("[ERROR] Could not save totals");
        return;
    }

    struct Record r = {currentIncome, currentExpense};

    fwrite(&r, sizeof(struct Record), 1, fp);

    fclose(fp);
}

// Primary author: Urvashi Panwala
// Description: Loads current income and expense totals from file
// Vulnerability Instance ID 6-1 (Failure to Handle Errors Correctly) `fread()` return value was not checked,
// which allowed uninitialized memory to be used as if it were valid.
// Resolution: Now checks that `fread()` successfully reads exactly 1 record.

void loadRecord()
{
    FILE *fp = fopen(CONFIG_RECORD_FILE, "rb");
    if (!fp)
    {
        fprintf(stderr, "[INFO] No record data found.\n");
        return;
    }

    struct Record r;
    size_t got = fread(&r, sizeof(r), 1, fp);
    if (got != 1)
    {
        fprintf(stderr,
                "[ERROR] Failed to read record from %s (got %zu of 1)\n",
                CONFIG_RECORD_FILE, got);
        fclose(fp);
        return;
    }

    currentIncome = r.income;
    currentExpense = r.expense;
    fclose(fp);
}

// Primary author: Urvashi Panwala
// Description: Frees all nodes in a linked list to prevent memory leaks

void freeList(struct Node *list)
{

    struct Node *tmp;

    while (list)
    {

        tmp = list;

        list = list->next;

        free(tmp);
    }
}

// Primary author: Isha Sheth
// Description: Displays the main menu to prompt registration or login or exit
// Inputs: user selection 1-3
// Outputs: Prompts user to select registration, login, or exit

void showMainMenu()
{

    printf("\n==== Welcome to Finance Tracker ====\n");

    printf("1. Register\n2. Login\n3. Exit\nChoose an option: ");
}

// Primary author: Isha Sheth
// Description: Displays post-login finance dashboard with options
// Inputs: User selection (1-5)
// Outputs: Triggers action based on user choice

void showFinanceMenu()
{

    printf("\n==== Finance Dashboard ====\n");

    printf("Total Income: %.2lf | Total Expense: %.2lf | Balance: %.2lf\n",

           currentIncome, currentExpense, currentIncome - currentExpense);

    printf("1. Add Income\n2. Add Expense\n3. View Income\n4. View Expense\n5. Logout\n");

    printf("Choose an option: ");
}

// Primary author: Isha Sheth
// Description: Entry point for the Finance Tracker.
// Loads saved records and data, manages authentication, and
// launches the finance dashboard loop after successful login.

// Vulnerability Instance ID 5-1 (Command Injection) allowed users to run arbitrary shell commands using system(cmd);
// Resolution: This functionality has been removed entirely in the secure version to prevent abuse.

// Vulnerability Instance ID 11-1 (Executing Code with Too Much Privilege) authenticated users could access a shell via `system(cmd);`, which let them execute arbitrary OS-level commands.
// This violated the principle of least privilege — users were allowed to perform actions outside the scope of the finance tracker
// Resolution: The code block using `system()` was removed entirely from the secure version.

int main()
{

    loadRecord();

    loadIncome();

    loadExpense();

    int choice, loggedIn = 0;

    while (!loggedIn)
    {

        showMainMenu();

        if (scanf("%d", &choice) != 1)
        {

            clearStdin();
            continue;
        }

        clearStdin();

        switch (choice)
        {

        case 1:
            registerUser();
            break;

        case 2:
            loggedIn = loginUser();
            break;

        case 3:
            exit(0);

        default:
            printf("[INFO] Invalid option.\n");
        }
    }

    do
    {

        showFinanceMenu();

        if (scanf("%d", &choice) != 1)
        {

            clearStdin();
            continue;
        }

        clearStdin();

        switch (choice)
        {

        case 1:
            addIncome();
            break;

        case 2:
            addExpense();
            break;

        case 3:
            displayRecords(incomeList, "Income");
            break;

        case 4:
            displayRecords(expenseList, "Expense");
            break;

        case 5:
            saveRecord();
            break;

        default:
            printf("Invalid choice.\n");
        }

    } while (choice != 5);

    freeList(incomeList);

    freeList(expenseList);

    printf("[INFO] Exiting Finance Tracker.\n");

    return 0;
}
