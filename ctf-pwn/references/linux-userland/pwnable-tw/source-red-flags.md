# pwnable.tw Source Red Flags

Generic vulnerable-code patterns extracted from the pwnable.tw source archive. Challenge-specific addresses and exploit chains remain in the sibling case files.

## How To Use

Use this file when inspecting source or decompiled-like pseudocode and a concrete unsafe API, lifetime shape, bounds calculation, allocator lifetime, or oracle is visible. It identifies reusable red flags only; exact addresses, libc versions, historical paths, flags, and provenance remain in the sibling case files.

## Red-Flag Router

| Pattern | Search signal | Vulnerability meaning | Consequence |
|---|---|---|---|
| [1.1](#pattern-11-fixed-size-buffer-with-unboundedmismatched-read-length) | `read`, `memcpy`, destination size | Requested read/copy exceeds fixed destination capacity. | Stack/global overflow and control-data corruption. |
| [1.2](#pattern-12-unsafe-string-input-functions-gets-scanfs-strcpy) | `gets`, `scanf("%s")`, `strcpy` | String input has no maximum-width boundary. | Buffer overflow through attacker-controlled length/content. |
| [1.3](#pattern-13-user-controlled-element-count-without-array-bound-check) | element count, loop bound | User chooses count but the array is not bounds-checked. | OOB stack/heap writes past the intended array. |
| [1.4](#pattern-14-string-expansion-via-formatting-sprintf--strcat) | `sprintf`, `strcat` | Destination capacity ignores source expansion/appended bytes. | Overflow while building formatted or concatenated output. |
| [1.5](#pattern-15-realpath-destination-buffer-overflow) | `realpath` | Destination buffer is smaller than expanded canonical path. | Path-expansion overflow. |
| [2.1](#pattern-21-post-read-nul-termination-at-buffer-capacity-index) | NUL, `buf[size]` | NUL is written at capacity rather than the last valid byte. | Single-byte overflow, often metadata corruption. |
| [2.2](#pattern-22-strncat-destination-buffer-boundary-miscalculation) | `strncat` | Size accounting omits append/NUL semantics. | Off-by-null or bounded-string overflow. |
| [2.3](#pattern-23-array-boundary-fencepost-error--instead-of-) | `<=`, `<` | Fencepost comparison permits one extra iteration. | Adjacent slot/global overwrite. |
| [3.1](#pattern-31-missing-pointer-nullification-after-free) | `free` | Freed pointer remains usable. | UAF, double free, stale function/data pointer. |
| [3.2](#pattern-32-reallocation-with-zero-size-reallocptr-0) | `realloc(ptr,0)` | Zero-size realloc frees while caller treats result as live. | Hidden free, UAF, tcache poisoning. |
| [3.3](#pattern-33-shallow-copy--missing-c-copy-constructor) | copy constructor, pass by value | Shallow copy shares owned resources; temporary destructor frees them. | Double free/UAF in C++ objects. |
| [3.4](#pattern-34-unchecked-repetitive-deallocation) | repeat delete/free | Deallocation state is not tracked. | Double free and allocator metadata reuse. |
| [3.5](#pattern-35-duplicate-deallocation-across-error-handling-paths) | error/free paths | Success and error paths both release the same resource. | Double free on controlled error. |
| [4.1](#pattern-41-signed-integer-index-comparison-missing-lower-bound-check) | signed index | Only upper bound is checked or signedness is wrong. | Negative-index OOB read/write. |
| [4.2](#pattern-42-unchecked-menudispatch-function-pointer-table-lookup) | menu, dispatch table | User index is not checked against table bounds. | OOB function pointer/data call. |
| [4.3](#pattern-43-stack-pointer--index-underflow-in-expression-parsers) | expression parser, operand index | Parser decrements or underflows a stack index. | Arbitrary stack read/write. |
| [4.4](#pattern-44-unchecked-directory--collection-stack-popping) | pop, collection stack | Pop/count operations lack underflow checks. | OOB access or state confusion. |
| [5.1](#pattern-51-reading-raw-bytes-without-appending-nul-terminator-before-string-output) | read then printf/puts | Raw bytes are not terminated before string output. | Adjacent memory information leak. |
| [5.2](#pattern-52-allocating-structs-with-malloc-leaving-pointer-fields-uninitialized) | malloc struct | Pointer fields are not initialized after allocation. | Stale-pointer leak/UAF. |
| [5.3](#pattern-53-unchecked-return-value-of-input-parsing-scanf--strtol) | `scanf`, `strtol` | Parse failure leaves old/partial value in use. | Stale state, type confusion, bypass. |
| [5.4](#pattern-54-stack-frame-reuse-without-zeroing) | stack reuse | Reused frame is treated as initialized. | Residual pointer/data leak and overwrite chaining. |
| [6.1](#pattern-61-user-input-passed-directly-as-format-specifier) | `printf(user)` | User controls format specifier. | Arbitrary read/write and control flow. |
| [7.1](#pattern-71-unsafe-static-downcasting-without-type-verification) | static_cast/downcast | Type tag is not verified before downcast. | Type confusion and forged vtable/fields. |
| [7.2](#pattern-72-copy-assignment-operator-returning-by-value) | `operator=` by value | Temporary copy invokes destructor on live resource. | UAF/double free. |
| [8.1](#pattern-81-inserting-stack-allocated-structs-into-heap-managed-linked-lists) | stack object in heap list | Heap container stores stack-local object. | Lifetime mismatch and unlink/control-frame corruption. |
| [8.2](#pattern-82-double-linked-list-unlink-with-unvalidated-pointers) | unlink, prev/next | Linked-list pointers are unvalidated. | Arbitrary write through unlink. |
| [9.1](#pattern-91-strncmp-using-user-input-length-as-comparison-bound) | `strncmp` | User supplies comparison length or empty input short-circuits it. | Authentication bypass and byte oracle. |
| [9.2](#pattern-92-side-channel-oracles-via-program-termination-state) | exit/crash/timing | Termination/time reveals comparison state. | Byte-by-byte secret or ASLR recovery. |


## Pattern 1.1: Fixed-Size Buffer with Unbounded/Mismatched Read Length
The requested read byte count is larger than the destination buffer capacity on the stack.
```c
void vulnerable_function(void) {
    char stack_buf[0x20]; // 32 bytes allocated

    // Flaw: reads 0x80 (128) bytes into a 32-byte buffer
    ssize_t bytes_read = read(STDIN_FILENO, stack_buf, 0x80);
}
```

## Pattern 1.2: Unsafe String Input Functions (`gets`, `scanf("%s")`, `strcpy`)
Reading string inputs without specifying maximum width or checking destination length.
```c
void vulnerable_string_input(void) {
    char user_input[64];

    // Flaw: gets() has no length check and reads until newline
    gets(user_input);

    // Flaw: scanf("%s") reads until whitespace without boundary limits
    scanf("%s", user_input);
}
```

## Pattern 1.3: User-Controlled Element Count Without Array Bound Check
Iterating over a user-supplied count into a fixed stack array.
```c
void process_items(void) {
    int item_array[16];
    unsigned int count;

    scanf("%u", &count); // User controls iteration count

    // Flaw: count can exceed 16, corrupting stack canary and return address
    for (unsigned int i = 0; i < count; i++) {
        scanf("%d", &item_array[i]);
    }
}
```

## Pattern 1.4: String Expansion via Formatting (`sprintf` / `strcat`)
Concatenating or expanding input strings into an insufficiently sized buffer.
```c
void format_message(const char *prefix, const char *suffix) {
    char output[64];

    // Flaw: combined length of prefix + suffix can exceed sizeof(output)
    sprintf(output, "%s: %s", prefix, suffix);
}
```

## Pattern 1.5: `realpath` Destination Buffer Overflow
Passing the same heap buffer as both input and output to `realpath()`, or providing an undersized output buffer.
```c
void resolve_path(char *input_path) {
    char *resolved = malloc(64); // Undersized buffer

    // Flaw: realpath can write up to PATH_MAX (4096) bytes into 'resolved',
    // overflowing the allocated heap chunk
    if (realpath(input_path, resolved) != NULL) {
        puts(resolved);
    }
}
```

---

## Pattern 2.1: Post-Read NUL-Termination at Buffer Capacity Index
Placing a string terminator at index `size` rather than `size - 1` after reading `size` bytes.
```c
void read_user_string(void) {
    char buffer[64];

    // Flaw: reads up to 64 bytes into indexes 0..63, then writes '\0' at buffer[64]
    ssize_t len = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (len > 0) {
        buffer[len] = '\0'; // Overwrites the byte immediately after buffer
    }
}
```

## Pattern 2.2: `strncat` Destination Buffer Boundary Miscalculation
Passing remaining capacity as `count` parameter to `strncat`, which always appends an additional NUL byte.
```c
void append_description(char *desc_buf, size_t max_buf_size, const char *new_text) {
    size_t current_len = strlen(desc_buf);
    size_t remaining_space = max_buf_size - current_len;

    // Flaw: strncat appends up to 'remaining_space' characters PLUS a terminating '\0'
    // If new_text length >= remaining_space, '\0' is written at desc_buf[max_buf_size]
    strncat(desc_buf, new_text, remaining_space);
}
```

## Pattern 2.3: Array Boundary Fencepost Error (`<=` instead of `<`)
Using an inclusive upper bound check on array indices.
```c
#define MAX_ITEMS 8
struct Item *registry[MAX_ITEMS];

int add_item(struct Item *new_item) {
    // Flaw: registry has elements 0..7; i == 8 writes out of bounds into adjacent memory
    for (int i = 0; i <= MAX_ITEMS; i++) {
        if (registry[i] == NULL) {
            registry[i] = new_item;
            return i;
        }
    }
    return -1;
}
```

---

## Pattern 3.1: Missing Pointer Nullification After Free
Freeing dynamic memory without clearing the global or container pointer reference.
```c
struct Object {
    void (*handler)(struct Object *);
    char *data;
};

struct Object *global_slots[10];

void delete_slot(int index) {
    if (global_slots[index] != NULL) {
        free(global_slots[index]->data);
        free(global_slots[index]);
        // Flaw: global_slots[index] is not set to NULL
    }
}

void use_slot(int index) {
    // Flaw: dereferences dangling pointer and calls controlled function pointer
    if (global_slots[index] != NULL) {
        global_slots[index]->handler(global_slots[index]);
    }
}
```

## Pattern 3.2: Reallocation with Zero Size (`realloc(ptr, 0)`)
Calling `realloc(ptr, 0)` deallocates `ptr` under glibc, equivalent to `free(ptr)`. If the return value is ignored or the old pointer is preserved, a dangling pointer is created.
```c
void resize_buffer(int slot_id, size_t new_size) {
    // Flaw: When new_size == 0, glibc realloc frees entries[slot_id].ptr and returns NULL
    void *new_ptr = realloc(entries[slot_id].ptr, new_size);

    if (new_ptr != NULL) {
        entries[slot_id].ptr = new_ptr;
        entries[slot_id].size = new_size;
    }
    // If new_size == 0, entries[slot_id].ptr remains non-NULL pointing to freed chunk
}
```

## Pattern 3.3: Shallow Copy / Missing C++ Copy Constructor
In C++, copying an object with raw pointer members without defining a deep copy constructor or copy assignment operator leads to double ownership of the same heap chunk.
```c++
class DynamicResource {
public:
    char *buffer;
    DynamicResource(size_t sz) { buffer = new char[sz]; }
    ~DynamicResource() { delete[] buffer; }
    // Flaw: Default copy constructor creates shallow copy of 'buffer'
};

void process_event() {
    DynamicResource res1(128);
    {
        DynamicResource res2 = res1; // Shallow copy of pointer
    } // res2 is destroyed -> buffer is freed

    // res1.buffer is now a dangling pointer (Use-After-Free)
    res1.buffer[0] = 'A';
}
```

## Pattern 3.4: Unchecked Repetitive Deallocation
Allowing the user to trigger deallocation multiple times on the same object slot without checking whether it is already freed.
```c
void *slot_table[8];

void free_entry(int id) {
    // Flaw: Does not check if slot_table[id] was already freed
    if (id >= 0 && id < 8 && slot_table[id] != NULL) {
        free(slot_table[id]);
        // Flaw: slot_table[id] is NOT set to NULL, allowing repeated calls to free()
    }
}
```

## Pattern 3.5: Duplicate Deallocation Across Error Handling Paths
Freeing a pointer in a local failure branch and again during general cleanup.
```c
int process_transaction(void) {
    char *session_data = malloc(256);

    if (authenticate_user() != 0) {
        free(session_data); // First free
        goto cleanup;       // Jumps to cleanup handler
    }

    return 0;

cleanup:
    free(session_data);     // Flaw: Second free on same pointer
    return -1;
}
```

---

## Pattern 4.1: Signed Integer Index Comparison (Missing Lower Bound Check)
Using a signed integer with only an upper boundary check allows negative indices to index backwards.
```c
#define TABLE_SIZE 10
void *entry_table[TABLE_SIZE];

void set_entry(int index, void *data) {
    // Flaw: 'index' is signed; negative values (e.g. index = -15) satisfy (index < 10)
    if (index < TABLE_SIZE) {
        entry_table[index] = data; // Writes to memory preceding entry_table (e.g. GOT)
    }
}
```

## Pattern 4.2: Unchecked Menu/Dispatch Function Pointer Table Lookup
Using user-supplied choice integers directly as indices into an array of function pointers.
```c
typedef void (*handler_t)(void);
handler_t command_handlers[5] = {cmd_view, cmd_edit, cmd_save, cmd_help, cmd_exit};

void dispatch_command(void) {
    int choice;
    scanf("%d", &choice);

    // Flaw: 'choice' is not validated against [0, 4]; arbitrary memory is called
    command_handlers[choice]();
}
```

## Pattern 4.3: Stack Pointer / Index Underflow in Expression Parsers
Decrementing an index or stack pointer during syntax parsing or evaluation without verifying that elements exist.
```c
int operand_stack[100];
int stack_top = 0;

void evaluate_binary_operator(char op) {
    // Flaw: If the expression starts with an operator without prior operands,
    // stack_top is decremented past 0, indexing negative stack memory
    int right = operand_stack[--stack_top];
    int left  = operand_stack[--stack_top];

    int result = (op == '+') ? (left + right) : (left - right);
    operand_stack[stack_top++] = result;
}
```

## Pattern 4.4: Unchecked Directory / Collection Stack Popping
Popping elements from a dynamic stack or list without verifying that the count is positive, leading to OOB free.
```c
char **directory_stack;
int dir_stack_count;

void pop_directory(void) {
    // Flaw: If dir_stack_count is already 0, --dir_stack_count becomes -1
    // freeing directory_stack[-1] (memory preceding the array)
    free(directory_stack[--dir_stack_count]);
}
```

---

## Pattern 5.1: Reading Raw Bytes Without Appending NUL-Terminator Before String Output
Using `read()` or `recv()` which do not append `\0`, followed by string-printing functions.
```c
void leak_stack_data(void) {
    char name_buffer[32];

    // Flaw: read() does NOT append '\0' to name_buffer
    read(STDIN_FILENO, name_buffer, 32);

    // Flaw: printf("%s") prints continuously until a NUL byte is found,
    // leaking residual stack pointers (canaries, libc return addresses)
    printf("Welcome: %s\n", name_buffer);
}
```

## Pattern 5.2: Allocating Structs with `malloc` Leaving Pointer Fields Uninitialized
Allocating memory with `malloc()` instead of `calloc()` and failing to initialize pointer members before use.
```c
struct Node {
    char title[32];
    struct Node *next; // Pointer to next node
};

struct Node *create_node(const char *title) {
    // Flaw: malloc() leaves memory uninitialized with stale heap contents
    struct Node *n = (struct Node *)malloc(sizeof(struct Node));
    strncpy(n->title, title, sizeof(n->title) - 1);

    // Flaw: n->next is not set to NULL; if reused, contains stale pointer
    return n;
}
```

## Pattern 5.3: Unchecked Return Value of Input Parsing (`scanf` / `strtol`)
Assuming input parsing always succeeds, leaving destination variables with uninitialized stack residue upon parse errors.
```c
void get_user_id(void) {
    int user_id; // Uninitialized stack variable

    // Flaw: If the user inputs non-numeric characters (e.g. "+", "-"),
    // scanf returns 0 without writing to user_id, leaving stack garbage/canary intact
    scanf("%d", &user_id);

    process_user(user_id);
}
```

## Pattern 5.4: Stack Frame Reuse Without Zeroing
Sequential function calls in the same stack frame where a buffer in the second function inherits data from the first.
```c
void setup_context(void) {
    void *sensitive_ptr = get_libc_pointer();
    // sensitive_ptr resides at offset [RBP - 0x20]
}

void prompt_name(void) {
    char name[16]; // Allocated at [RBP - 0x20]
    read(STDIN_FILENO, name, 16); // Overwrites low bytes, leaves high bytes intact
    puts(name); // Leaks remaining high bytes of sensitive_ptr
}
```

---

## Pattern 6.1: User Input Passed Directly as Format Specifier
Passing a variable containing user input directly as the first argument to `printf`.
```c
void echo_message(void) {
    char message[128];
    fgets(message, sizeof(message), stdin);

    // Flaw: 'message' is evaluated as the format string instead of a string argument
    // Correct usage: printf("%s", message);
    printf(message);
}
```

---

## Pattern 7.1: Unsafe Static Downcasting Without Type Verification
Casting a base class pointer to an arbitrary derived class pointer based on unverified user choices.
```c++
class BaseTask {
public:
    virtual void run() = 0;
};

class FileTask : public BaseTask {
public:
    char *filepath;
    void run() override { puts(filepath); }
};

class MathTask : public BaseTask {
public:
    int calculation_id;
    void run() override { printf("ID: %d\n", calculation_id); }
};

void execute_task(BaseTask *task, int assumed_type) {
    // Flaw: If task is a MathTask but assumed_type indicates FileTask,
    // math fields are treated as heap pointers, leading to arbitrary memory read/dereference
    if (assumed_type == 1) {
        FileTask *ft = static_cast<FileTask *>(task);
        puts(ft->filepath);
    }
}
```

## Pattern 7.2: Copy Assignment Operator Returning by Value
Defining `operator=` to return a new copy by value instead of a reference (`Class&`), which constructs a temporary object whose destructor immediately runs and frees the underlying resource.
```c++
class DataContainer {
public:
    char *buffer;
    size_t size;

    // Flaw: Returns by value (DataContainer) instead of reference (DataContainer&)
    DataContainer operator=(const DataContainer &other) {
        if (this != &other) {
            delete[] this->buffer;
            this->size = other.size;
            this->buffer = new char[this->size];
            memcpy(this->buffer, other.buffer, this->size);
        }
        return *this; // Flaw: Creates a temporary object; temporary destructor frees buffer
    }

    ~DataContainer() {
        delete[] buffer;
    }
};
```

---

## Pattern 8.1: Inserting Stack-Allocated Structs into Heap-Managed Linked Lists
Mixing dynamic memory management with stack storage in the same data collection.
```c
struct ListNode {
    int value;
    struct ListNode *next;
    struct ListNode *prev;
};

struct ListNode *global_head = NULL;

void add_special_item(void) {
    struct ListNode stack_node; // Allocated on the current stack frame
    stack_node.value = 1337;

    // Flaw: Inserts pointer to stack_node into global list
    stack_node.next = global_head;
    stack_node.prev = NULL;
    if (global_head) global_head->prev = &stack_node;
    global_head = &stack_node;

    // When add_special_item returns, stack_node frame is invalidated
}

void clear_list(void) {
    struct ListNode *curr = global_head;
    while (curr) {
        struct ListNode *next = curr->next;
        free(curr); // Flaw: Calls free() on stack memory address
        curr = next;
    }
}
```

## Pattern 8.2: Double-Linked List Unlink with Unvalidated Pointers
Unlinking an item whose `prev` and `next` pointers reside in memory controlled by user input or stack variables.
```c
void remove_node(struct ListNode *node) {
    // Flaw: If node's prev/next pointers are attacker-controlled,
    // this performs an arbitrary write: *(node->next->prev) = node->prev
    if (node->next) node->next->prev = node->prev;
    if (node->prev) node->prev->next = node->next;
}
```

---

## Pattern 9.1: `strncmp` Using User Input Length as Comparison Bound
Comparing a stored secret against user input using `strlen(user_input)` as the comparison length.
```c
int check_password(const char *stored_password) {
    char user_input[64];
    read(STDIN_FILENO, user_input, sizeof(user_input));

    // Flaw: If user sends an empty string or '\0', strlen(user_input) is 0,
    // causing strncmp to return 0 (Success) without checking any password bytes.
    // Sending 1 byte allows brute-forcing the password one byte at a time.
    if (strncmp(stored_password, user_input, strlen(user_input)) == 0) {
        return 1; // Authenticated
    }
    return 0;
}
```

## Pattern 9.2: Side-Channel Oracles via Program Termination State
Allowing an attacker to deduce memory contents by observing crash versus infinite loop or exit status differences.
```c
void oracle_probe(unsigned char guess, unsigned char *target_byte) {
    // Flaw: Side-channel timing/state oracle
    if (*target_byte == guess) {
        while (1); // Program hangs (State A)
    } else {
        exit(1);   // Program exits immediately (State B)
    }
}
```
