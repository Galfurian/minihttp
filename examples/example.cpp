#include <iostream>
#include <fstream>

#include "minihttp/minihttp.hpp"

int main(int argc, const char *argv[])
{
    try {
        std::string uri;
        std::string method = "GET";
        std::string arguments;
        std::string output;
        http::InternetProtocol protocol = http::InternetProtocol::V4;

        for (int i = 1; i < argc; ++i) {
            const std::string arg = std::string(argv[i]);

            if (arg == "--help") {
                std::cout << "example --url <url> [--protocol <protocol>] [--method <method>] [--arguments <arguments>] [--output <output>]\n";
                return EXIT_SUCCESS;
            } else if (arg == "--uri") {
                if (++i < argc)
                    uri = argv[i];
                else
                    throw std::runtime_error("Missing argument for --url");
            } else if (arg == "--protocol") {
                if (++i < argc) {
                    if (std::string(argv[i]) == "ipv4")
                        protocol = http::InternetProtocol::V4;
                    else if (std::string(argv[i]) == "ipv6")
                        protocol = http::InternetProtocol::V6;
                    else
                        throw std::runtime_error("Invalid protocol");
                } else
                    throw std::runtime_error("Missing argument for --protocol");
            } else if (arg == "--method") {
                if (++i < argc)
                    method = argv[i];
                else
                    throw std::runtime_error("Missing argument for --method");
            } else if (arg == "--arguments") {
                if (++i < argc)
                    arguments = argv[i];
                else
                    throw std::runtime_error("Missing argument for --arguments");
            } else if (arg == "--output") {
                if (++i < argc)
                    output = argv[i];
                else
                    throw std::runtime_error("Missing argument for --output");
            } else
                throw std::runtime_error("Invalid flag: " + arg);
        }

        http::Request request(uri, protocol);
        http::HeaderFields fields;
        fields.push_back(http::HeaderField("Content-Type", "application/x-www-form-urlencoded"));
        fields.push_back(http::HeaderField("User-Agent", "runscope/0.1"));
        fields.push_back(http::HeaderField("Accept", "*/*"));

        const http::Response response = request.send(method, arguments, fields, 4000);

        if (response.status.status_code == http::Status::Ok) {
            if (!output.empty()) {
                std::ofstream outfile(output.c_str(), std::ofstream::binary);
                outfile.write(reinterpret_cast<const char *>(response.body.data()),
                              static_cast<std::streamsize>(response.body.size()));
            } else {
                std::cout << std::string(response.body.begin(), response.body.end()) << '\n';
            }
        } else {
            std::cout << "Request failed : " << response.status.reason_phrase << "\n";
        }
    } catch (const http::RequestError &e) {
        std::cerr << "Request error: " << e.what() << '\n';
        return EXIT_FAILURE;
    } catch (const http::ResponseError &e) {
        std::cerr << "Response error: " << e.what() << '\n';
        return EXIT_FAILURE;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
