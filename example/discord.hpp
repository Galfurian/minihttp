/// @file discord.hpp
/// @author Enrico Fraccaroli (enry.frak@gmail.com)
/// @brief 

#include "json/json.hpp"

#include <string>
#include <vector>

namespace discord
{
struct Author {
    /// Name of author.
    std::string name;
    /// URL of author. If name was used, it becomes a hyperlink.
    std::string url;
    /// URL of author icon.
    std::string icon_url;
};

struct EmbedImage {
    /// URL of image.
    std::string url;
};

struct EmbedField {
    /// Name of the field.
    std::string name;
    /// Value of the field.
    std::string value;
    /// If true, fields will be displayed in same line, but there can only be 3 max in same line or 2 max if you used thumbnail
    bool inline_field;
};

struct EmbedFooter {
    /// Footer text, doesn't support Markdown.
    std::string text;
    /// URL of author icon.
    std::string icon_url;
};

struct Embed {
    /// Embed author object.
    Author author;
    /// Title of embed.
    std::string title;
    /// URL of embed. If title was used, it becomes hyperlink
    std::string url;
    /// Description text.
    std::string description;
    /// Color code of the embed. You have to use Decimal numeral system, not Hexadecimal. Use color picker and converter.
    int color;
    /// Array of embed field objects.
    std::vector<EmbedField> fields;
    /// Embed thumbnail object.
    EmbedImage thumbnail;
    /// Embed image object.
    EmbedImage image;
    /// Embed footer object.
    EmbedFooter footer;
};

struct Message {
    /// If used, it overrides the default username of the webhook.
    std::string username;
    /// If used, it overrides the default avatar of the webhook.
    std::string avatar_url;
    /// Simple message, the message contains (up to 2000 characters).
    std::string content;
    /// Array of embed objects. That means, you can use more than one in the same body.
    std::vector<Embed> embeds;
};

} // namespace discord


template <>
json::jnode_t &json::operator<<(json::jnode_t &lhs, const discord::Author &rhs)
{
    lhs.set_type(json::JOBJECT);
    lhs["name"] << rhs.name;
    lhs["url"] << rhs.url;
    lhs["icon_url"] << rhs.icon_url;
    return lhs;
}

template <>
const json::jnode_t &json::operator>>(const json::jnode_t &lhs, discord::Author &rhs)
{
    lhs["name"] >> rhs.name;
    lhs["url"] >> rhs.url;
    lhs["icon_url"] >> rhs.icon_url;
    return lhs;
}

template <>
json::jnode_t &json::operator<<(json::jnode_t &lhs, const discord::EmbedImage &rhs)
{
    lhs.set_type(json::JOBJECT);
    lhs["url"] << rhs.url;
    return lhs;
}

template <>
const json::jnode_t &json::operator>>(const json::jnode_t &lhs, discord::EmbedImage &rhs)
{
    lhs["url"] >> rhs.url;
    return lhs;
}

template <>
json::jnode_t &json::operator<<(json::jnode_t &lhs, const discord::EmbedField &rhs)
{
    lhs.set_type(json::JOBJECT);
    lhs["name"] << rhs.name;
    lhs["value"] << rhs.value;
    lhs["inline"] << rhs.inline_field;
    return lhs;
}

template <>
const json::jnode_t &json::operator>>(const json::jnode_t &lhs, discord::EmbedField &rhs)
{
    lhs["name"] >> rhs.name;
    lhs["value"] >> rhs.value;
    lhs["inline"] >> rhs.inline_field;
    return lhs;
}

template <>
json::jnode_t &json::operator<<(json::jnode_t &lhs, const discord::EmbedFooter &rhs)
{
    lhs.set_type(json::JOBJECT);
    lhs["text"] << rhs.text;
    lhs["icon_url"] << rhs.icon_url;
    return lhs;
}

template <>
const json::jnode_t &json::operator>>(const json::jnode_t &lhs, discord::EmbedFooter &rhs)
{
    lhs["text"] >> rhs.text;
    lhs["icon_url"] >> rhs.icon_url;
    return lhs;
}

template <>
json::jnode_t &json::operator<<(json::jnode_t &lhs, const discord::Embed &rhs)
{
    lhs.set_type(json::JOBJECT);
    lhs["author"] << rhs.author;
    lhs["title"] << rhs.title;
    lhs["url"] << rhs.url;
    lhs["description"] << rhs.description;
    lhs["color"] << rhs.color;
    lhs["fields"] << rhs.fields;
    lhs["thumbnail"] << rhs.thumbnail;
    lhs["image"] << rhs.image;
    lhs["footer"] << rhs.footer;
    return lhs;
}

template <>
const json::jnode_t &json::operator>>(const json::jnode_t &lhs, discord::Embed &rhs)
{
    lhs["author"] >> rhs.author;
    lhs["title"] >> rhs.title;
    lhs["url"] >> rhs.url;
    lhs["description"] >> rhs.description;
    lhs["color"] >> rhs.color;
    lhs["fields"] >> rhs.fields;
    lhs["thumbnail"] >> rhs.thumbnail;
    lhs["image"] >> rhs.image;
    lhs["footer"] >> rhs.footer;
    return lhs;
}

template <>
json::jnode_t &json::operator<<(json::jnode_t &lhs, const discord::Message &rhs)
{
    lhs.set_type(json::JOBJECT);
    lhs["username"] << rhs.username;
    lhs["avatar_url"] << rhs.avatar_url;
    lhs["content"] << rhs.content;
    lhs["embeds"] << rhs.embeds;
    return lhs;
}

template <>
const json::jnode_t &json::operator>>(const json::jnode_t &lhs, discord::Message &rhs)
{
    lhs["username"] >> rhs.username;
    lhs["avatar_url"] >> rhs.avatar_url;
    lhs["content"] >> rhs.content;
    lhs["embeds"] >> rhs.embeds;
    return lhs;
}
