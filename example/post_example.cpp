#include <iostream>
#include <fstream>

#include "minihttp/minihttp.hpp"
#include "discord.hpp"

int main(int argc, const char *argv[])
{
    if (argc != 2) {
        std::cerr << "Usage :\n";
        std::cerr << "    " << argv[0] << " <discord-webhook>\n";
        return 1;
    }

#if 0
    discord::Message message{
        "Webhook",
        "https://i.imgur.com/4M34hi2.png",
        "Text message. Up to 2000 characters.",
        { discord::Embed{
            discord::Author{
                "Birdie♫",
                "https://www.reddit.com/r/cats/",
                "https://i.imgur.com/R66g1Pe.jpg" },
            "Title",
            "https://google.com/",
            "Text message. You can use Markdown here. *Italic* **bold** __underline__ ~~strikeout~~ [hyperlink](https://google.com) `code`",
            15258703,
            { discord::EmbedField{
                  "Text",
                  "More text",
                  true },
              discord::EmbedField{
                  "Even more text",
                  "Yup",
                  true },
              discord::EmbedField{
                  "Use `inline: true` parameter, if you want to display fields in the same line.",
                  "okay...",
                  false },
              discord::EmbedField{
                  "Thanks!",
                  "You're welcome :wink:",
                  false } },
            discord::EmbedImage{
                "https://upload.wikimedia.org/wikipedia/commons/3/38/4-Nature-Wallpapers-2014-1_ukaavUI.jpg" },
            discord::EmbedImage{
                "https://upload.wikimedia.org/wikipedia/commons/5/5a/A_picture_from_China_every_day_108.jpg" },
            discord::EmbedFooter{
                "Woah! So cool! :smirk:",
                "https://i.imgur.com/fKL31aD.jpg" } } }
    };
    json::jnode_t jroot;
    jroot << message;
#else
    json::jnode_t jroot;
    jroot.set_type(json::JOBJECT);
    jroot["content"] << "test";
#endif

    try {
        std::string uri    = argv[1];
        std::string method = "POST";

        http::Request request(uri, http::InternetProtocol::V4);
        http::HeaderFields fields;
        fields.push_back(http::HeaderField("Content-Type", "application/json"));
        fields.push_back(http::HeaderField("User-Agent", "runscope/0.1"));

        const http::Response response = request.send(method, jroot.to_string(false), fields, 4000);

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
