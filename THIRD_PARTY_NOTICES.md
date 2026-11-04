# Third-party notices

Abigail's own source is licensed under the repository's [MIT license](LICENSE).
The vendored code below retains ProjectDiscovery's MIT license and copyright
notice. Other compiled dependencies are listed in [licenses/NOTICE.md](licenses/NOTICE.md).

## ProjectDiscovery Subfinder v2.17.0

Abigail includes a modified copy of Subfinder's passive discovery engine in
`third_party/subfinder`. The original source is
<https://github.com/projectdiscovery/subfinder/tree/v2.17.0>. Abigail changed
package import paths and patched its HTTP agent to verify HTTPS certificates,
block cross-origin redirects, and protect credentials in logs. The modified
source is available in Abigail's public repository. License: MIT. The upstream
license notice follows verbatim.

```text
MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
