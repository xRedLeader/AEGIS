using System.Diagnostics;
class Fixture {
  public void Unsafe(string command) {
    Process.Start(command);
  }
  public void Safe(string text) {
    System.Console.WriteLine(text);
  }
}
