#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

// Large resource-like data embedded in the binary
static const char embedded_html[] =
    "<html><head><title>DefenderAtlas</title></head>\n"
    "<body><h1>Research Dataset</h1>\n"
    "<p>This is embedded data for PE analysis.</p>\n"
    "<table border='1'>\n"
    "<tr><th>ID</th><th>Name</th><th>Value</th><th>Status</th></tr>\n"
    // Repeat pattern to create large data
    "<tr><td>001</td><td>Sample_A</td><td>1234.56</td><td>Active</td></tr>\n"
    "<tr><td>002</td><td>Sample_B</td><td>2345.67</td><td>Active</td></tr>\n"
    "<tr><td>003</td><td>Sample_C</td><td>3456.78</td><td>Inactive</td></tr>\n"
    "<tr><td>004</td><td>Sample_D</td><td>4567.89</td><td>Active</td></tr>\n"
    "<tr><td>005</td><td>Sample_E</td><td>5678.90</td><td>Pending</td></tr>\n"
    "<tr><td>006</td><td>Sample_F</td><td>6789.01</td><td>Active</td></tr>\n"
    "<tr><td>007</td><td>Sample_G</td><td>7890.12</td><td>Inactive</td></tr>\n"
    "<tr><td>008</td><td>Sample_H</td><td>8901.23</td><td>Active</td></tr>\n"
    "</table>\n"
    "</body></html>\n";

static const char embedded_json[] =
    "{\"dataset\":\"DefenderAtlas\",\"version\":\"1.0\",\"samples\":[\n"
    "{\"id\":1,\"name\":\"alpha\",\"size\":1024,\"hash\":\"abc123\"},\n"
    "{\"id\":2,\"name\":\"bravo\",\"size\":2048,\"hash\":\"def456\"},\n"
    "{\"id\":3,\"name\":\"charlie\",\"size\":4096,\"hash\":\"ghi789\"},\n"
    "{\"id\":4,\"name\":\"delta\",\"size\":8192,\"hash\":\"jkl012\"},\n"
    "{\"id\":5,\"name\":\"echo\",\"size\":16384,\"hash\":\"mno345\"},\n"
    "{\"id\":6,\"name\":\"foxtrot\",\"size\":32768,\"hash\":\"pqr678\"},\n"
    "{\"id\":7,\"name\":\"golf\",\"size\":65536,\"hash\":\"stu901\"},\n"
    "{\"id\":8,\"name\":\"hotel\",\"size\":131072,\"hash\":\"vwx234\"}\n"
    "]}\n";

static const char embedded_xml[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<configuration>\n"
    "  <appSettings>\n"
    "    <add key=\"MaxRetries\" value=\"3\" />\n"
    "    <add key=\"Timeout\" value=\"30000\" />\n"
    "    <add key=\"BufferSize\" value=\"4096\" />\n"
    "    <add key=\"DebugEnabled\" value=\"true\" />\n"
    "    <add key=\"LogLevel\" value=\"Info\" />\n"
    "    <add key=\"MaxConnections\" value=\"100\" />\n"
    "    <add key=\"CacheSize\" value=\"1048576\" />\n"
    "    <add key=\"CompressionEnabled\" value=\"false\" />\n"
    "  </appSettings>\n"
    "  <system.web>\n"
    "    <compilation debug=\"true\" targetFramework=\"4.8\" />\n"
    "    <httpRuntime targetFramework=\"4.8\" maxRequestLength=\"51200\" />\n"
    "  </system.web>\n"
    "</configuration>\n";

// Binary data block
static unsigned char binary_block[204800];

// CSV-like data
static char csv_data[102400];

void init_binary_block() {
    for (int i = 0; i < 204800; i++) {
        binary_block[i] = (unsigned char)((i * 31 + 17) ^ (i >> 3)) & 0xFF;
    }
}

void generate_csv() {
    int pos = 0;
    pos += sprintf(csv_data + pos, "ID,Name,Category,Size,Hash,Status,Priority\n");
    const char* categories[] = {"Alpha","Bravo","Charlie","Delta","Echo"};
    const char* statuses[] = {"Active","Inactive","Pending","Error","Done"};
    for (int i = 0; i < 2000; i++) {
        pos += sprintf(csv_data + pos,
            "%d,Sample_%04d,%s,%d,hash_%04x,%s,%d\n",
            i, i, categories[i % 5], 1024 + i * 64,
            i * 37 & 0xFFFF, statuses[i % 5], i % 10);
    }
}

int main() {
    printf("Category D: Large Resource-like Data\n");
    printf("Binary contains embedded HTML, JSON, XML, CSV, and binary data\n\n");

    init_binary_block();
    generate_csv();

    printf("Embedded HTML: %zu bytes\n", strlen(embedded_html));
    printf("Embedded JSON: %zu bytes\n", strlen(embedded_json));
    printf("Embedded XML: %zu bytes\n", strlen(embedded_xml));
    printf("Binary block: %d bytes\n", (int)sizeof(binary_block));
    printf("CSV data: %zu bytes\n", strlen(csv_data));

    printf("\n--- HTML Preview ---\n%.200s...\n", embedded_html);
    printf("\n--- JSON Preview ---\n%.200s...\n", embedded_json);
    printf("\n--- CSV First 10 Lines ---\n");
    int lines = 0;
    for (int i = 0; csv_data[i] && lines < 10; i++) {
        putchar(csv_data[i]);
        if (csv_data[i] == '\n') lines++;
    }

    printf("\n--- Binary Block Checksum ---\n");
    unsigned int sum = 0;
    for (int i = 0; i < 204800; i++) {
        sum += binary_block[i];
    }
    printf("  Sum: %u\n", sum);

    printf("\n=== Complete ===\n");
    return 0;
}
