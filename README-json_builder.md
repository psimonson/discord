# json_builder.h

A lightweight, feature-rich JSON parser and builder library for C with zero dependencies.

## Features

- **JSON Parsing** - Fast, single-pass JSON parser with token-based API
- **JSON Building** - Intuitive builder API for constructing JSON documents
- **Pretty Printing** - Format JSON with customizable indentation
- **Streaming Support** - Parse JSON incrementally as data arrives
- **Path-Based Insertion** - Insert values at specific paths (e.g., `user.array[3]`)
- **Unlimited Nesting** - Dynamic stack eliminates depth limitations
- **Header-Only** - Single file, just `#define JSON_IMPLEMENTATION`
- **Zero Dependencies** - Only uses standard C library

## Quick Start

```c
#define JSON_IMPLEMENTATION
#include "json_builder.h"

// Build JSON
char buffer[1024];
json_builder_t builder;
json_builder_init(&builder, buffer, sizeof(buffer));

json_builder_object_begin(&builder);
json_builder_key(&builder, "name");
json_builder_string(&builder, "John Doe");
json_builder_key(&builder, "age");
json_builder_int(&builder, 30);
json_builder_object_end(&builder);

printf("%s\n", json_builder_get_string(&builder));
// Output: {"name":"John Doe","age":30}

json_builder_free(&builder);
```

## Building JSON

### Basic Values

```c
json_builder_string(&builder, "text");      // String
json_builder_int(&builder, 42);             // Integer
json_builder_double(&builder, 3.14);        // Floating point
json_builder_bool(&builder, true);          // Boolean
json_builder_null(&builder);                // null
json_builder_raw(&builder, "[1,2,3]");      // Raw JSON
```

### Objects

```c
json_builder_object_begin(&builder);
json_builder_key(&builder, "field");
json_builder_string(&builder, "value");
json_builder_object_end(&builder);
```

### Arrays

```c
json_builder_array_begin(&builder);
json_builder_int(&builder, 1);
json_builder_int(&builder, 2);
json_builder_int(&builder, 3);
json_builder_array_end(&builder);
```

### Pretty Printing

```c
json_builder_enable_pretty_print(&builder, 2);  // 2-space indent

// Output:
// {
//   "name": "John",
//   "age": 30
// }
```

## Parsing JSON

```c
const char *json = "{\"name\":\"John\",\"age\":30}";
json_parser_t parser;
json_token_t tokens[128];

json_parser_init(&parser);
int num_tokens = json_parse(&parser, json, strlen(json), tokens, 128);

// Extract values
for (int i = 0; i < num_tokens; i++) {
    if (tokens[i].type == JSON_STRING) {
        char value[256];
        json_token_strcpy(json, &tokens[i], value, sizeof(value));
        printf("String: %s\n", value);
    }
}
```

### Helper Functions

```c
int json_token_strcmp(const char *js, const json_token_t *tok, const char *s);
int json_token_to_int(const char *js, const json_token_t *tok, int *out);
int json_token_to_int64(const char *js, const json_token_t *tok, int64_t *out);
int json_token_to_double(const char *js, const json_token_t *tok, double *out);
bool json_token_is_true(const char *js, const json_token_t *tok);
bool json_token_is_false(const char *js, const json_token_t *tok);
bool json_token_is_null(const char *js, const json_token_t *tok);
```

## Streaming Parser

Process JSON data as it arrives (useful for network streams):

```c
json_stream_parser_t stream;
json_token_t tokens[100];
char buffer[1024];

json_stream_parser_init(&stream, tokens, 100, buffer, sizeof(buffer));

// Feed data chunks
json_stream_parser_feed(&stream, chunk1, len1);
json_stream_parser_feed(&stream, chunk2, len2);

if (json_stream_parser_is_complete(&stream)) {
    // Process tokens
}
```

## Path-Based Insertion

Insert values into existing JSON at specific paths:

```c
const char *input = "{\"user\":{\"array\":[1,2,3,4]}}";
char output[512];

// Insert after array[2] (between 3 and 4)
json_insert_path(input, "user.array[2]", "99", output, sizeof(output));
// Result: {"user":{"array":[1,2,3,99,4]}}

// Insert before array[0]
json_insert_path_ex(input, "user.array[0]", "99", 
                    JSON_INSERT_BEFORE, output, sizeof(output));
// Result: {"user":{"array":[99,1,2,3,4]}}
```

## Pretty Printing Utilities

```c
// Pretty print existing JSON
char pretty[1024];
json_pretty_print(compact_json, pretty, sizeof(pretty), 4);

// Minify JSON
char minified[512];
json_minify(pretty_json, minified, sizeof(minified));
```

## Error Handling

All functions return `json_error_t`:

```c
typedef enum {
    JSON_ERROR_NONE = 0,        // Success
    JSON_ERROR_NOMEM = -1,      // Out of memory
    JSON_ERROR_INVAL = -2,      // Invalid input
    JSON_ERROR_PART = -3,       // Incomplete JSON
    JSON_ERROR_BUFFER_FULL = -4,// Output buffer full
    JSON_ERROR_MAX_DEPTH = -5   // Max nesting depth
} json_error_t;
```

Example:

```c
json_error_t err = json_builder_string(&builder, "value");
if (err != JSON_ERROR_NONE) {
    fprintf(stderr, "Error: %d\n", err);
}
```

## Custom Memory Allocation

Override the default allocator:

```c
#define JSON_MALLOC my_malloc
#define JSON_FREE my_free
#define JSON_REALLOC my_realloc
#define JSON_IMPLEMENTATION
#include "json_builder.h"
```

## Configuration

```c
// Initialize with custom stack capacity
json_builder_init_dynamic(&builder, buffer, size, 64);

// Custom format options
json_format_t format = {
    .enabled = true,
    .indent_size = 4,
    .indent_char = ' ',
    .space_after_colon = true,
    .space_after_comma = true,
    .trailing_newline = true
};
json_builder_set_format(&builder, &format);
```

## Complete Example

```c
#define JSON_IMPLEMENTATION
#include "json_builder.h"
#include <stdio.h>

int main() {
    char buffer[1024];
    json_builder_t builder;
    
    json_builder_init(&builder, buffer, sizeof(buffer));
    json_builder_enable_pretty_print(&builder, 2);
    
    json_builder_object_begin(&builder);
    
    json_builder_key(&builder, "users");
    json_builder_array_begin(&builder);
    
    json_builder_object_begin(&builder);
    json_builder_key(&builder, "name");
    json_builder_string(&builder, "Alice");
    json_builder_key(&builder, "age");
    json_builder_int(&builder, 30);
    json_builder_object_end(&builder);
    
    json_builder_object_begin(&builder);
    json_builder_key(&builder, "name");
    json_builder_string(&builder, "Bob");
    json_builder_key(&builder, "age");
    json_builder_int(&builder, 25);
    json_builder_object_end(&builder);
    
    json_builder_array_end(&builder);
    json_builder_object_end(&builder);
    
    printf("%s\n", json_builder_get_string(&builder));
    
    json_builder_free(&builder);
    return 0;
}
```

## License

MIT License - See file header for details.

## Version

2.0 - Enhanced with unlimited nesting, streaming, and path insertion.