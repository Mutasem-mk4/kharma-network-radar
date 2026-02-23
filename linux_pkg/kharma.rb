class Kharma < Formula
  desc "Elite proactive network defense suite with real-time radar and DPI"
  homepage "https://github.com/Mutasem-mk4/kharma-network-radar"
  url "https://files.pythonhosted.org/packages/source/k/kharma-radar/kharma_radar-10.2.0.tar.gz"
  sha256 "SKIP" # User should update this with the actual SHA-256 after publishing

  depends_on "python@3.10"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/kharma", "--version"
  end
end
