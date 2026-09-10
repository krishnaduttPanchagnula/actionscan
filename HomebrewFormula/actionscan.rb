class Actionscan < Formula
  desc "Scan GitHub repos for vulnerable, malicious, and outdated GitHub Actions"
  homepage "https://github.com/krishnaduttPanchagnula/actionscan"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/krishnaduttPanchagnula/actionscan/releases/download/v1.0.0/actionscan_MacOS_x86_64.tar.gz"
      sha256 "..."
    end
    if Hardware::CPU.arm?
      url "https://github.com/krishnaduttPanchagnula/actionscan/releases/download/v1.0.0/actionscan_MacOS_ARM64.tar.gz"
      sha256 "..."
    end
  end

  on_linux do
    if Hardware::CPU.intel? and Hardware::CPU.is_64_bit?
      url "https://github.com/krishnaduttPanchagnula/actionscan/releases/download/v1.0.0/actionscan_Linux_x86_64.tar.gz"
      sha256 "..."
    end
    if Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "https://github.com/krishnaduttPanchagnula/actionscan/releases/download/v1.0.0/actionscan_Linux_ARM64.tar.gz"
      sha256 "..."
    end
  end

  def install
    bin.install "actionscan"
  end

  test do
    system "#{bin}/actionscan --help"
  end
end
