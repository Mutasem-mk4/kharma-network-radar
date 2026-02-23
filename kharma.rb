class Kharma < Formula
  desc "Elite Proactive Defense & Enterprise-Grade Network Intelligence"
  homepage "https://github.com/Mutasem-mk4/kharma-network-radar"
  url "https://github.com/Mutasem-mk4/kharma-network-radar/releases/download/v10.2.0/kharma_radar-10.2.0.tar.gz"
  sha256 "458b5c5ded314facae6db671bb118bb54f792bd9c64914fe853419a49f5af4a4"
  license "MIT"

  depends_on "python@3.12"
  depends_on "libpcap"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/kharma", "--version"
  end
end
