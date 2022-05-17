#include <iostream>
#include <fstream>

#include "minihttp.hpp"

int main(int, const char *[])
{
    try {
        std::string uri       = "https://discord.com/api/webhooks/...";
        std::string method    = "GET";
        std::string arguments = "";

        http::Request request(uri, http::InternetProtocol::V4);
        http::HeaderFields fields;
        fields.push_back(http::HeaderField("Content-Type", "application/x-www-form-urlencoded"));
        fields.push_back(http::HeaderField("User-Agent", "runscope/0.1"));
        fields.push_back(http::HeaderField("Accept", "*/*"));

        const http::Response response = request.send(method, arguments, fields, 4000);

        if (response.status.status_code == http::Status::Ok) {
            std::cout << std::string(response.body.begin(), response.body.end()) << '\n';
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
