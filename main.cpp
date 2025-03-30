#include "httplib.h"
#include <pqxx/pqxx>
#include <nlohmann/json.hpp>
#include <curl/curl.h>

using json = nlohmann::json;
using namespace nlohmann::json_literals;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

json call_sbom_sh(const std::string& repo_url) {
    CURL* curl = curl_easy_init();
    json result;

    if (curl) {
        std::string readBuffer;
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.sbom.sh/scan");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ("repo_url=" + repo_url).c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        result = json::parse(readBuffer);
    }
    return result;
}

int main() {
    httplib::Server svr;

    svr.Post("/api/repos", [](const httplib::Request &req, httplib::Response &res) {
        auto body = json::parse(req.body);
        std::string repo_url = body["repo_url"];
        std::string schedule = body["schedule"];

        json scan_result = call_sbom_sh(repo_url);

        pqxx::connection c{"dbname=mydb user=myuser password=mypass"};
        pqxx::work txn{c};
        txn.exec0("INSERT INTO repos (url, schedule, latest_scan) VALUES ("
                   + txn.quote(repo_url) + ", " + txn.quote(schedule) + ", " + txn.quote(scan_result.dump()) + ")");
        txn.commit();

        json response = { {"repo_id", repo_url}, {"status", "registered"} };
        res.set_content(response.dump(), "application/json");
    });

    svr.Get(R"(/api/repos/(.+)/scans)", [](const httplib::Request &req, httplib::Response &res) {
        std::string repo_id = req.matches[1];

        pqxx::connection c{"dbname=mydb user=myuser password=mypass"};
        pqxx::work txn{c};
        auto r = txn.exec1("SELECT latest_scan FROM repos WHERE url=" + txn.quote(repo_id));

        json scans = json::parse(r[0].as<std::string>());
        json response = { {"scans", scans} };

        res.set_content(response.dump(), "application/json");
    });

    svr.Delete(R"(/api/repos/(.+))", [](const httplib::Request &req, httplib::Response &res) {
        std::string repo_id = req.matches[1];

        pqxx::connection c{"dbname=mydb user=myuser password=mypass"};
        pqxx::work txn{c};
        txn.exec0("DELETE FROM repos WHERE url = " + txn.quote(repo_id));
        txn.commit();

        json response = { {"repo_id", repo_id}, {"status", "deregistered"} };
        res.set_content(response.dump(), "application/json");
    });

    svr.listen("0.0.0.0", 8080);
    return 0;
}