#include <iostream>
#include <fstream>

#include "minihttp.hpp"

int main(int, const char *[])
{
    try {
        std::string uri    = "https://discord.com/api/webhooks/...";
        std::string method = "POST";
        std::string arguments =
            "{\r\n"
            "  \"username\": \"Webhook\",\r\n"
            "  \"avatar_url\": \"https://i.imgur.com/4M34hi2.png\",\r\n"
            "  \"content\": \"Text message. Up to 2000 characters.\",\r\n"
            "  \"embeds\": [\r\n"
            "    {\r\n"
            "      \"author\": {\r\n"
            "        \"name\": \"Birdie♫\",\r\n"
            "        \"url\": \"https://www.reddit.com/r/cats/\",\r\n"
            "        \"icon_url\": \"https://i.imgur.com/R66g1Pe.jpg\"\r\n"
            "      },\r\n"
            "      \"title\": \"Title\",\r\n"
            "      \"url\": \"https://google.com/\",\r\n"
            "      \"description\": \"Text message. You can use Markdown here. *Italic* **bold** __underline__ ~~strikeout~~ [hyperlink](https://google.com) `code`\",\r\n"
            "      \"color\": 15258703,\r\n"
            "      \"fields\": [\r\n"
            "        {\r\n"
            "          \"name\": \"Text\",\r\n"
            "          \"value\": \"More text\",\r\n"
            "          \"inline\": true\r\n"
            "        },\r\n"
            "        {\r\n"
            "          \"name\": \"Even more text\",\r\n"
            "          \"value\": \"Yup\",\r\n"
            "          \"inline\": true\r\n"
            "        },\r\n"
            "        {\r\n"
            "          \"name\": \"Use `inline: true` parameter, if you want to display fields in the same line.\",\r\n"
            "          \"value\": \"okay...\"\r\n"
            "        },\r\n"
            "        {\r\n"
            "          \"name\": \"Thanks!\",\r\n"
            "          \"value\": \"You're welcome :wink:\"\r\n"
            "        }\r\n"
            "      ],\r\n"
            "      \"thumbnail\": {\r\n"
            "        \"url\": \"https://upload.wikimedia.org/wikipedia/commons/3/38/4-Nature-Wallpapers-2014-1_ukaavUI.jpg\"\r\n"
            "      },\r\n"
            "      \"image\": {\r\n"
            "        \"url\": \"https://upload.wikimedia.org/wikipedia/commons/5/5a/A_picture_from_China_every_day_108.jpg\"\r\n"
            "      },\r\n"
            "      \"footer\": {\r\n"
            "        \"text\": \"Woah! So cool! :smirk:\",\r\n"
            "        \"icon_url\": \"https://i.imgur.com/fKL31aD.jpg\"\r\n"
            "      }\r\n"
            "    }\r\n"
            "  ]\r\n"
            "}\r\n";

        http::Request request(uri, http::InternetProtocol::V4);
        http::HeaderFields fields;
        fields.push_back(http::HeaderField("Content-Type", "application/json"));
        fields.push_back(http::HeaderField("User-Agent", "runscope/0.1"));

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
