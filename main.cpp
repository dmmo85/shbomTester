#include "httplib.h"
#include <iostream>

using namespace httplib;

int main()
{
    Server svr;

    svr.Get("/hi", [](const Request & /*req*/, Response &res) {
      res.set_content("Hello World!", "text/plain");
    });
  
    svr.listen("0.0.0.0", 8080);

    return 0;
}
